"""The audit log: one hash-chained record per decision (spec/SPEC.md section 8).

Records are JSON lines; ``prev`` is the digest of the previous record, so a gap, an edit or a reordering is
detected by :func:`verify_records`. With a ``signer`` (the monitor's own Ed25519 key), every record also
carries ``kid`` and ``sig``, so a reader with the monitor's public key can tell a real record from a
fabricated one: a hash chain alone can be rebuilt by anyone. :func:`to_syslog` formats a record as an
RFC 5424 line for a SIEM.
"""
from __future__ import annotations

import json
import os
import socket
from typing import Any, Iterable

from . import canonical, keys
from .ledger import _Lock

GENESIS = "sha256:" + "0" * 64
SCHEMA_ID = "smartagency.audit/1"


class AuditLog:
    def __init__(self, path: str | None = None, signer=None):
        self.path = path
        self.signer = signer
        self._kid = keys.key_id(signer.public_key()) if signer is not None else None
        self.records: list[dict] = []
        self._prev = GENESIS
        self._size = 0
        if path and os.path.exists(path):
            self._reload()

    def _reload(self) -> None:
        """Read and verify the whole file (raises ValueError)."""
        try:
            with open(self.path, "rb") as f:
                data = f.read()
            records = [json.loads(line) for line in data.split(b"\n") if line.strip()]
        except (OSError, UnicodeDecodeError, ValueError, RecursionError) as e:
            raise ValueError(f"{self.path}: not a readable audit log ({type(e).__name__})") from None
        if data and not data.endswith(b"\n"):
            raise ValueError(f"{self.path}: the last record has no newline (an interrupted write?)")
        verify_records(records)
        self.records, self._size = records, len(data)
        self._prev = canonical.digest(records[-1]) if records else GENESIS

    def append(self, record: dict) -> dict:
        """Append one record. With a file, under a lock, after catching up with other writers."""
        with _Lock(self.path):
            if self.path and not os.path.exists(self.path) and self.records:
                raise ValueError(f"{self.path} disappeared; refusing to start a new audit file mid-chain")
            if self.path and os.path.exists(self.path) and os.path.getsize(self.path) != self._size:
                self._reload()
            r = {"schema": SCHEMA_ID, "seq": len(self.records), "prev": self._prev, **record}
            if self.signer is not None:
                r["kid"] = self._kid
                r["sig"] = keys.sign(self.signer, canonical.encode(r))
            data = canonical.encode(r) + b"\n"
            if self.path:
                with open(self.path, "ab") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                self._size += len(data)
            self.records.append(r)
            self._prev = canonical.digest(r)
        return r


def verify_records(records: Iterable[Any]) -> None:
    prev = GENESIS
    for i, r in enumerate(records):
        if not isinstance(r, dict) or r.get("schema") != SCHEMA_ID or r.get("seq") != i or r.get("prev") != prev:
            raise ValueError(f"audit record {i}: broken chain (missing, edited or reordered record)")
        prev = canonical.digest(r)


def record_signed_by(record: Any, registry) -> bool:
    """True when ``record`` carries a valid signature by a key the registry trusts at the record's time.
    Pass a registry of **monitor keys only**, never the issuer registry: any key in it is accepted."""
    from .contract import parse_time
    if not isinstance(record, dict) or not isinstance(record.get("kid"), str) or not isinstance(record.get("sig"), str):
        return False
    try:
        at = parse_time(record.get("at"))
        body = canonical.encode({k: v for k, v in record.items() if k != "sig"})
    except (ValueError, TypeError):
        return False
    pub = registry.public_key(record["kid"], at)
    return pub is not None and keys.verify(pub, body, record["sig"])


_SEVERITY = {"allow": 6, "escalate": 4, "deny": 5}   # informational, warning, notice


def to_syslog(record: dict, app: str = "sf-smartagency", host: str | None = None) -> str:
    """RFC 5424 line: facility 13 (log audit), severity by outcome, the record as structured JSON message."""
    pri = 13 * 8 + _SEVERITY.get(record.get("outcome", ""), 5)
    host = host or socket.gethostname() or "-"
    msg = canonical.encode(record).decode("utf-8")
    return f"<{pri}>1 {record.get('at', '-')} {host} {app} - {record.get('outcome', '-')} - {msg}"
