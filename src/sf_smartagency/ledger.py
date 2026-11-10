"""The status ledger: an append-only, hash-chained, signed record of what happened to each contract
(spec/SPEC.md section 6).

Each line of a ledger file is one entry:

    {"schema": "smartagency.ledger/1", "seq": 0, "prev": "sha256:000...", "at": "2026-10-26T09:00:00Z",
     "event": "issue", "contract_id": "...", "contract_digest": "sha256:...", "kid": "ed25519:...",
     "sig": "<base64url>"}

Events: ``issue`` (optional ``supersedes``), ``suspend``, ``resume``, ``revoke_grants`` (``grants``: grant
indexes), ``revoke`` (final). Every entry is signed by the contract's issuer; ``prev`` is the digest of the
previous entry, so removing, reordering or editing any entry breaks the chain. A ledger that does not
verify is an error: the monitor then denies everything (fail closed).
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime
from typing import Any

from . import canonical, keys
from .contract import format_time, parse_time

SCHEMA_ID = "smartagency.ledger/1"
GENESIS = "sha256:" + "0" * 64
EVENTS = ("issue", "suspend", "resume", "revoke_grants", "revoke")
_BASE = {"schema", "seq", "prev", "at", "event", "contract_id", "contract_digest", "kid", "sig"}
_OPTIONAL = {"issue": {"supersedes", "reason"}, "suspend": {"reason"}, "resume": {"reason"},
             "revoke_grants": {"grants", "reason"}, "revoke": {"reason"}}
MAX_LINE = 64 * 1024


class LedgerError(ValueError):
    pass


class StatusLedger:
    """``anchor`` is a head this ledger must contain ("<seq>:<digest>", from :meth:`head`), kept somewhere the
    ledger's writer cannot change. Without it, a rollback of the whole file to an older valid copy can only
    be detected by a process that has already read the newer entries. ``must_exist`` refuses a missing file."""

    def __init__(self, registry, path: str | None = None, *, anchor: str | None = None, must_exist: bool = False):
        self.registry = registry
        self.path = path
        self.anchor = anchor
        self.entries: list[dict] = []
        self._state: dict[str, dict] = {}
        self._stamp = None
        if path and os.path.exists(path):
            self._load()
        elif path and must_exist:
            raise LedgerError(f"{path} does not exist")
        elif anchor is not None:
            self._check_anchor()

    def head(self) -> str:
        """``<seq>:<digest>`` of the last entry: store it outside the ledger's reach and pass it as ``anchor``."""
        if not self.entries:
            return "-1:" + GENESIS
        return f"{len(self.entries) - 1}:{canonical.digest(self.entries[-1])}"

    def _check_anchor(self) -> None:
        if self.anchor is None:
            return
        try:
            seq_s, dig = self.anchor.split(":", 1)
            seq = int(seq_s)
        except (ValueError, AttributeError):
            raise LedgerError("anchor must be '<seq>:<digest>'") from None
        if seq == -1 and dig == GENESIS:
            return
        if not 0 <= seq < len(self.entries) or canonical.digest(self.entries[seq]) != dig:
            raise LedgerError("the ledger does not contain its anchor: it was rolled back or replaced")

    # ------------------------------------------------------------------ reading
    def _load(self) -> None:
        entries, state = [], {}
        try:
            stamp = _file_stamp(self.path)
            f = open(self.path, "rb")
        except OSError as e:
            raise LedgerError(f"{self.path}: {e.strerror}") from None
        with f:
            for n, raw in enumerate(f, 1):
                if len(raw) > MAX_LINE:
                    raise LedgerError(f"{self.path}:{n}: line longer than {MAX_LINE} bytes")
                if not raw.endswith(b"\n"):
                    raise LedgerError(f"{self.path}:{n}: the last line has no newline (an interrupted write?)")
                try:
                    entry = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, ValueError, RecursionError) as e:
                    raise LedgerError(f"{self.path}:{n}: not JSON ({type(e).__name__})") from None
                try:
                    self._apply(state, entries, entry)
                    if canonical.encode(entry) + b"\n" != raw:
                        raise LedgerError("line is not in canonical form (the file was edited)")
                except LedgerError as e:
                    raise LedgerError(f"{self.path}:{n}: {e}") from None
                entries.append(entry)
        known = self.entries
        if entries[:len(known)] != known:
            raise LedgerError(f"{self.path}: the ledger shrank or was rewritten since it was read")
        self.entries, self._state = entries, state
        self._stamp = stamp
        self._check_anchor()

    def refresh(self) -> None:
        """Reload the file if another process changed it since it was read (raises LedgerError)."""
        if not self.path:
            return
        if not os.path.exists(self.path):
            if self.entries or self.anchor is not None:
                raise LedgerError(f"{self.path} disappeared")
            return
        if _file_stamp(self.path) != self._stamp:
            self._load()

    def verify(self) -> None:
        """Re-verify every entry from the start (raises LedgerError)."""
        state, entries = {}, []
        for i, e in enumerate(self.entries):
            try:
                self._apply(state, entries, e)
            except LedgerError as err:
                raise LedgerError(f"entry {i}: {err}") from None
            entries.append(e)

    def status(self, contract_id: str, at: datetime) -> dict:
        """Replay the entries dated at or before ``at``: {status, digest, issuer, revoked_grants}."""
        if not self.entries or at >= parse_time(self.entries[-1]["at"]):
            state = self._state                            # the common case: the latest state
        else:
            state = {}
            for e in self.entries:
                if parse_time(e["at"]) > at:
                    break
                _transition(state, e)
        s = state.get(contract_id)
        if s is None:
            return {"status": "unknown", "digest": None, "issuer": None, "revoked_grants": []}
        return {"status": s["status"], "digest": s["digest"], "issuer": s["issuer"],
                "revoked_grants": sorted(s["revoked_grants"])}

    # ------------------------------------------------------------------ writing
    def record(self, private, event: str, contract_id: str, contract_digest: str, at: datetime | str,
               *, grants: list[int] | None = None, supersedes: str | None = None, reason: str | None = None) -> dict:
        """Build, sign, check and append one entry. Returns the entry."""
        at_s = at if isinstance(at, str) else format_time(at)
        with _Lock(self.path):
            if self.path and os.path.exists(self.path):
                self._load()
            elif self.path and self.entries:
                raise LedgerError(f"{self.path} disappeared; refusing to start a new file")                                   # another writer may have appended
            e: dict[str, Any] = {"schema": SCHEMA_ID, "seq": len(self.entries),
                                 "prev": canonical.digest(self.entries[-1]) if self.entries else GENESIS,
                                 "at": at_s, "event": event, "contract_id": contract_id,
                                 "contract_digest": contract_digest, "kid": keys.key_id(private.public_key())}
            if grants is not None:
                e["grants"] = grants
            if supersedes is not None:
                e["supersedes"] = supersedes
            if reason is not None:
                e["reason"] = reason
            e["sig"] = keys.sign(private, canonical.encode(e))
            self._apply(dict_copy(self._state), list(self.entries), e)   # check before writing anything
            if self.path:
                line = canonical.encode(e) + b"\n"
                with open(self.path, "ab") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            self._apply(self._state, self.entries, e)
            self.entries.append(e)
            if self.path:
                self._stamp = _file_stamp(self.path)
        return e

    def append(self, entry: dict) -> None:
        """Append an entry signed elsewhere (for example replicated from another node), after the same checks."""
        with _Lock(self.path):
            if self.path and os.path.exists(self.path):
                self._load()
            elif self.path and self.entries:
                raise LedgerError(f"{self.path} disappeared; refusing to start a new file")
            self._apply(dict_copy(self._state), list(self.entries), entry)
            if self.path:
                with open(self.path, "ab") as f:
                    f.write(canonical.encode(entry) + b"\n")
                    f.flush()
                    os.fsync(f.fileno())
            self._apply(self._state, self.entries, entry)
            self.entries.append(entry)
            if self.path:
                self._stamp = _file_stamp(self.path)

    # ------------------------------------------------------------------ checks
    def _apply(self, state: dict, entries: list, e: Any) -> None:
        if not isinstance(e, dict):
            raise LedgerError("entry is not an object")
        event = e.get("event")
        if event not in EVENTS:
            raise LedgerError(f"unknown event {event!r}")
        extra = set(e) - _BASE - _OPTIONAL[event]
        missing = _BASE - set(e)
        if extra or missing:
            raise LedgerError(f"fields: missing {sorted(missing)}, not allowed {sorted(extra)}")
        try:
            canonical.encode(e)
        except ValueError as err:
            raise LedgerError(str(err)) from None
        if e["schema"] != SCHEMA_ID:
            raise LedgerError("wrong schema")
        if type(e["seq"]) is not int or e["seq"] != len(entries):
            raise LedgerError(f"seq {e['seq']!r}, expected {len(entries)}")
        expected_prev = canonical.digest(entries[-1]) if entries else GENESIS
        if e["prev"] != expected_prev:
            raise LedgerError("prev does not match the previous entry (the chain is broken)")
        for f in ("at", "contract_id", "contract_digest", "kid", "sig"):
            if not isinstance(e[f], str):
                raise LedgerError(f"{f} must be a string")
        try:
            at = parse_time(e["at"])
        except ValueError:
            raise LedgerError("at must be YYYY-MM-DDTHH:MM:SSZ") from None
        if entries and at < parse_time(entries[-1]["at"]):
            raise LedgerError("at is earlier than the previous entry")
        if not e["contract_digest"].startswith("sha256:") or len(e["contract_digest"]) != 71:
            raise LedgerError("contract_digest must be sha256:<64 hex>")
        if "reason" in e and (not isinstance(e["reason"], str) or len(e["reason"]) > 500):
            raise LedgerError("reason must be a string of at most 500 characters")
        pub = self.registry.public_key(e["kid"], at)
        if pub is None:
            raise LedgerError(f"key {e['kid']} is not trusted at {e['at']}")
        body = {k: v for k, v in e.items() if k != "sig"}
        if not keys.verify(pub, canonical.encode(body), e["sig"]):
            raise LedgerError("signature does not verify")
        cid = e["contract_id"]
        s = state.get(cid)
        if event == "issue":
            if s is not None:
                raise LedgerError(f"contract {cid} was already issued")
            if "supersedes" in e:
                t = state.get(e["supersedes"])
                if t is None or t["issuer"] != e["kid"] or t["status"] in ("revoked", "superseded"):
                    raise LedgerError("supersedes must name a live contract of the same issuer")
        else:
            if s is None:
                raise LedgerError(f"contract {cid} was never issued")
            if e["kid"] != s["issuer"]:
                raise LedgerError("only the contract's issuer may change its status")
            if e["contract_digest"] != s["digest"]:
                raise LedgerError("contract_digest differs from the issued contract")
            if s["status"] in ("revoked", "superseded"):
                raise LedgerError(f"contract {cid} is {s['status']}: no further events")
            if event == "suspend" and s["status"] != "active":
                raise LedgerError("only an active contract can be suspended")
            if event == "resume" and s["status"] != "suspended":
                raise LedgerError("only a suspended contract can be resumed")
            if event == "revoke_grants":
                g = e.get("grants")
                if (not isinstance(g, list) or not g or len(g) > 256 or len(set(g)) != len(g)
                        or any(type(i) is not int or not 0 <= i < 256 for i in g)):
                    raise LedgerError("grants must be a non-empty list of distinct grant indexes (0-255)")
        _transition(state, e)


def _transition(state: dict, e: dict) -> None:
    cid, event = e["contract_id"], e["event"]
    if event == "issue":
        state[cid] = {"status": "active", "digest": e["contract_digest"], "issuer": e["kid"], "revoked_grants": set()}
        if "supersedes" in e:
            state[e["supersedes"]]["status"] = "superseded"
    elif event == "suspend":
        state[cid]["status"] = "suspended"
    elif event == "resume":
        state[cid]["status"] = "active"
    elif event == "revoke":
        state[cid]["status"] = "revoked"
    elif event == "revoke_grants":
        state[cid]["revoked_grants"] |= set(e["grants"])


def _file_stamp(path: str):
    st = os.stat(path)
    return (st.st_size, st.st_mtime_ns, st.st_ino)


def dict_copy(state: dict) -> dict:
    return {k: {**v, "revoked_grants": set(v["revoked_grants"])} for k, v in state.items()}


class _Lock:
    """A lock file next to the ledger, so two writers never interleave. No-op for an in-memory ledger."""

    def __init__(self, path: str | None):
        self.lock = path + ".lock" if path else None
        self.fd = None

    def __enter__(self):
        if not self.lock:
            return self
        for _ in range(100):
            try:
                self.fd = os.open(self.lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                return self
            except FileExistsError:
                time.sleep(0.05)
        raise LedgerError(f"{self.lock} is held by another writer (delete it if no writer is running)")

    def __exit__(self, *exc):
        if self.fd is not None:
            os.close(self.fd)
            os.unlink(self.lock)
        return False
