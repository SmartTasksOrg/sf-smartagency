"""The enforcement monitor: decides each action an agent asks to take (spec/SPEC.md section 7).

A decision is ``allow``, ``deny`` or ``escalate`` (a person must authorise it first), with reason codes:

    invalid-action        the subject, verb, resource, usage, influence, session or time is malformed
    ledger-invalid        the status ledger does not verify: everything is denied (fail closed)
    no-active-contract    no contract for this agent is signed, trusted, issued, live and in its time window
    denied-by-grant       a deny grant of an active contract matches (deny overrides allow, in any contract)
    no-matching-grant     no allow grant matches (default deny)
    limit-tokens, limit-tool-calls, limit-depth, limit-influence
                          the action exceeds the most restrictive limit among the contracts that allow it
    composite:<name>      with this action, the session completes a forbidden sequence
    pressure-locked       the agent released (SmartFabric atomic reset) and waits for a person's reset
    pressure-release      this action took the agent's pressure to the release threshold
    pressure-escalation   the agent's pressure is in SmartFabric's escalation zone (outcome: escalate)
    audit-unavailable     the audit record could not be written: the action is denied and no state changes

Pressure uses the most restrictive SmartFabric configuration among all of the agent's active contracts.
Checks run in that order and stop at the first deny. Only actions that reach the pressure step change the
agent's pressure and its session; the audit record is written before that state changes.

The monitor keeps pressure and sessions in memory: keep one Monitor in front of an agent for as long as it
runs. A new Monitor starts every agent at zero pressure and unlocked, so restarting the monitor process
clears a release lock without a person's reset. Restart it only when a person would also reset the agents,
or keep their contracts suspended until then. A Monitor is not thread-safe; serialise calls to it.

The monitor refuses to start (PressureStateError) if the installed SmartFabric does not carry the state it
is given (see _engine).
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from sf_smartfabric import PressureConfig, PressureEngine, Zone

from . import canonical, contract as C, keys
from .audit import AuditLog
from .ledger import LedgerError, StatusLedger

_SESSION_RE = re.compile(r"^[!-~]{1,256}$")


@dataclass
class Decision:
    outcome: str                                   # allow | deny | escalate
    reasons: list[str]
    contract_ids: list[str] = field(default_factory=list)
    pressure: str = "0"
    zone: str = Zone.NOMINAL.value

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"

    def to_dict(self) -> dict:
        return {"outcome": self.outcome, "reasons": self.reasons, "contract_ids": self.contract_ids,
                "pressure": self.pressure, "zone": self.zone}


def _fmt(p: float) -> str:
    s = f"{p:.6f}".rstrip("0").rstrip(".")
    return s or "0"


def merge_pressure(configs: list[PressureConfig]) -> PressureConfig:
    """Most restrictive of several configs: lowest thresholds and dissipation, highest coefficients."""
    if not configs:
        return PressureConfig()
    lo = lambda f: min(getattr(c, f) for c in configs)
    hi = lambda f: max(getattr(c, f) for c in configs)
    esc, rel = lo("escalation_threshold"), lo("release_threshold")
    if rel <= esc:                                   # keep the core's rule release > escalation
        esc = min(esc, max(0.0, rel - 0.01))
    return PressureConfig(escalation_threshold=esc, release_threshold=rel,
                          dissipation_per_step=lo("dissipation_per_step"),
                          token_coefficient=hi("token_coefficient"), tool_coefficient=hi("tool_coefficient"),
                          depth_coefficient=hi("depth_coefficient"),
                          warning_band=min(lo("warning_band"), esc))


class _Pressure:
    """Per-agent pressure (value + post-release lock), stepped with SmartFabric's PressureEngine."""

    def __init__(self, p: float = 0.0, locked: bool = False, cfg: PressureConfig | None = None):
        self.p, self.locked, self.cfg = p, locked, cfg

    def copy(self) -> "_Pressure":
        return _Pressure(self.p, self.locked, self.cfg)

    def zone(self) -> str:
        if self.locked:
            return Zone.RELEASE.value
        return PressureEngine(self.cfg).zone(self.p).value

    def step(self, cfg: PressureConfig, tokens: int, tool_calls: int, depth: int):
        eng = _engine(cfg, self.p, self.locked)
        out = eng.step(tokens=tokens, tool_calls=tool_calls, depth=depth)
        return out, eng.pressure, eng.locked


class PressureStateError(RuntimeError):
    """The installed SmartFabric does not take the agent's pressure state: the monitor refuses to decide."""


def _engine(cfg: PressureConfig, p: float, locked: bool) -> PressureEngine:
    """A SmartFabric engine carrying an agent's state. SmartFabric 0.5.x has no public way to set it, so this
    sets its two private fields and reads them back through the public properties. If a SmartFabric release
    stores its state elsewhere, every step would silently start from zero; this raises instead (fail closed)."""
    eng = PressureEngine(cfg)
    eng._p, eng._locked = p, locked
    if eng.pressure != p or eng.locked != locked:
        raise PressureStateError("the installed sf-smartfabric does not keep pressure in _p/_locked; "
                                 "this SmartAgency version cannot carry pressure with it")
    return eng


def _check_engine() -> None:
    """Startup self-test: state set on an engine must carry into a step, and a lock must hold."""
    cfg = PressureConfig()
    out = _engine(cfg, 0.5, False).step()
    if abs(out.pressure - (0.5 - cfg.dissipation_per_step)) > 1e-9:
        raise PressureStateError("the installed sf-smartfabric does not step from the state it was given")
    if not _engine(cfg, 0.0, True).step(tool_calls=1).locked:
        raise PressureStateError("the installed sf-smartfabric does not keep a release lock it was given")


class Monitor:
    def __init__(self, registry, ledger: StatusLedger, audit: AuditLog | None = None,
                 clock: Callable[[], datetime] | None = None):
        _check_engine()                                     # refuse to start on an incompatible SmartFabric
        self.registry = registry
        self.ledger = ledger
        self.audit = audit
        signer = getattr(audit, "signer", None)
        if signer is not None and keys.key_id(signer.public_key()) in registry.kids():
            raise ValueError("the audit signing key is an issuer key: a monitor key must never issue contracts")
        self.clock = clock or (lambda: datetime.now(timezone.utc).replace(microsecond=0))
        self._envelopes: dict[str, dict] = {}
        self._pressure: dict[str, _Pressure] = {}
        # session -> {digest of a rule's deny_sequence: number of leading patterns of the rule already seen}
        self._sessions: dict[tuple[str, str], dict[tuple[str, str], int]] = {}

    # ------------------------------------------------------------------ contracts
    def add_contract(self, envelope: dict, at: datetime | None = None) -> list[str]:
        """Verify a signed contract now (or at ``at``) and keep a copy. Returns problems; empty means kept."""
        at = at or self.clock()
        if not _aware(at):
            return ["at must be a timezone-aware datetime"]
        problems = C.envelope_problems(envelope, lambda kid: self.registry.public_key(kid, at))
        if problems:
            return problems
        cid = envelope["contract"]["id"]
        if cid in self._envelopes and self._envelopes[cid] != envelope:
            return [f"a different contract with id {cid} is already loaded"]
        self._envelopes[cid] = copy.deepcopy(envelope)
        return []

    def _loaded(self, subject: str) -> list[dict]:
        return [e["contract"] for e in self._envelopes.values() if e["contract"]["subject"] == subject]

    def active_contracts(self, subject: str, at: datetime) -> list[dict]:
        """Contracts for ``subject`` that are valid at ``at``, with revoked grants removed."""
        out = []
        for cid in sorted(self._envelopes):
            c = self._envelopes[cid]["contract"]
            if c["subject"] != subject:
                continue
            if self.registry.public_key(c["issuer"], at) is None:
                continue                                   # the issuer key is not trusted at this time
            st = self.ledger.status(cid, at)
            if st["status"] != "active" or st["digest"] != canonical.digest(c) or st["issuer"] != c["issuer"]:
                continue
            if not (C.parse_time(c["not_before"]) <= at < C.parse_time(c["expires"])):
                continue
            revoked = set(st["revoked_grants"])
            out.append({**c, "grants": [g for i, g in enumerate(c["grants"]) if i not in revoked]})
        return out

    # ------------------------------------------------------------------ decisions
    def check(self, subject: str, verb: str, resource: str, *, tokens: int = 0, tool_calls: int = 0,
              depth: int = 0, influence: str = "informational", session: str | None = None,
              at: datetime | None = None) -> Decision:
        at = at or self.clock()
        okay = _inputs_ok(subject, verb, resource, tokens, tool_calls, depth, influence, session, at)
        if okay:
            sess = self._sessions.get((subject, session), {}) if session is not None else {}
            pres = self._pressure.get(subject, _Pressure())
            d, new_pres, new_sess = self._decide(subject, verb, resource, tokens, tool_calls, depth, influence,
                                                 sess, pres, at)
        else:
            d, new_pres, new_sess = Decision("deny", ["invalid-action"]), None, None
        if self.audit is not None:                         # audit first: no state changes without a record
            try:
                self.audit.append({
                    "at": C.format_time(at) if _aware(at) else C.format_time(self.clock()),
                    "subject": subject[:256] if type(subject) is str else None,
                    "verb": verb[:64] if type(verb) is str else None,
                    "resource": resource[:256] if type(resource) is str else None,
                    "session": session if okay else None, **d.to_dict(),
                    "usage": {"tokens": tokens, "tool_calls": tool_calls, "depth": depth} if okay else None,
                    "influence": influence if okay else None})
            except (ValueError, OSError, LedgerError):
                return Decision("deny", ["audit-unavailable"], [], d.pressure, d.zone)
        if new_pres is not None:
            self._pressure[subject] = new_pres
            if session is not None:
                self._sessions[(subject, session)] = new_sess
        return d

    def check_plan(self, subject: str, steps: list, at: datetime | None = None) -> list[Decision]:
        """Decide a whole plan in order without changing any state. The plan is its own session, so
        composite rules apply across its steps; pressure starts from the agent's current pressure."""
        at = at or self.clock()
        if not isinstance(steps, list):
            return [Decision("deny", ["invalid-action"])]
        pres = self._pressure.get(subject, _Pressure()) if type(subject) is str else _Pressure()
        sess: dict = {}
        out = []
        for s in steps:
            args = (s.get("verb"), s.get("resource"), s.get("tokens", 0), s.get("tool_calls", 0), s.get("depth", 0),
                    s.get("influence", "informational")) if isinstance(s, dict) else (None,) * 6
            if not isinstance(s, dict) or not _inputs_ok(subject, *args, None, at):
                out.append(Decision("deny", ["invalid-action"]))
                continue
            d, new_pres, new_sess = self._decide(subject, *args, sess, pres, at)
            if new_pres is not None:
                pres, sess = new_pres, new_sess
            out.append(d)
        return out

    def reset(self, subject: str) -> None:
        """A person's reset after a release: clears the agent's pressure and lock (SmartFabric atomic reset)."""
        if type(subject) is not str:
            raise TypeError("subject must be a str")
        if self.audit is not None:
            self.audit.append({"at": C.format_time(self.clock()), "subject": subject[:256], "outcome": "reset",
                               "reasons": ["manual-reset"]})
        self._pressure.pop(subject, None)

    def end_session(self, subject: str, session: str) -> None:
        self._sessions.pop((subject, session), None)

    def _decide(self, subject, verb, resource, tokens, tool_calls, depth, influence, sess, pres: _Pressure, at):
        """Returns (decision, new pressure state or None, new session state or None). Changes nothing."""
        def report(d: Decision) -> Decision:
            d.pressure, d.zone = _fmt(pres.p), pres.zone()
            return d

        try:
            self.ledger.refresh()
        except (LedgerError, OSError):
            return report(Decision("deny", ["ledger-invalid"])), None, None
        active = self.active_contracts(subject, at)
        if not active:
            return report(Decision("deny", ["no-active-contract"])), None, None
        ids = [c["id"] for c in active]
        deny = sorted({c["id"] for c in active for g in c["grants"]
                       if g["effect"] == "deny" and C.action_matches(g, verb, resource)})
        if deny:
            return report(Decision("deny", ["denied-by-grant"], deny)), None, None
        allowing = [c for c in active
                    if any(g["effect"] == "allow" and C.action_matches(g, verb, resource) for g in c["grants"])]
        if not allowing:
            return report(Decision("deny", ["no-matching-grant"], ids)), None, None
        aids = [c["id"] for c in allowing]
        lim = {k: min(c["limits"][k] for c in allowing) for k in ("max_tokens", "max_tool_calls", "max_depth")}
        reasons = []
        if tokens > lim["max_tokens"]:
            reasons.append("limit-tokens")
        if tool_calls > lim["max_tool_calls"]:
            reasons.append("limit-tool-calls")
        if depth > lim["max_depth"]:
            reasons.append("limit-depth")
        if C.INFLUENCE.index(influence) > min(C.INFLUENCE.index(c["limits"]["max_influence"]) for c in allowing):
            reasons.append("limit-influence")
        if reasons:
            return report(Decision("deny", reasons, aids)), None, None
        # progress is kept per rule content, so a contract that supersedes another with the same rule keeps it
        rules = [(canonical.digest(r["deny_sequence"]), r["name"], r["deny_sequence"])
                 for c in active for r in c.get("composite", [])]
        hit = sorted({"composite:" + name for key, name, seq in rules
                      if sess.get(key, 0) == len(seq) - 1 and C.action_matches(seq[-1], verb, resource)})
        if hit:
            return report(Decision("deny", hit, ids)), None, None
        cfg = merge_pressure([C.pressure_config(c) for c in active])     # pressure is per agent: strictest of all
        if pres.locked:
            return report(Decision("deny", ["pressure-locked"], aids)), None, None
        out, p, locked = pres.step(cfg, tokens, tool_calls, depth)
        new_pres = _Pressure(p, locked, cfg)
        new_sess = dict(sess)
        tracked = {canonical.digest(r["deny_sequence"]): r["deny_sequence"] for c in self._loaded(subject)
                   for r in c.get("composite", [])}         # every loaded contract, active or not
        for key, seq in tracked.items():           # how far each forbidden sequence has got in this session
            k = new_sess.get(key, 0)
            if k < len(seq) - 1 and C.action_matches(seq[k], verb, resource):
                new_sess[key] = k + 1
        if out.released:
            d = Decision("deny", ["pressure-release"], aids, _fmt(p), Zone.RELEASE.value)
        elif out.zone == Zone.ESCALATION:
            d = Decision("escalate", ["pressure-escalation"], aids, _fmt(p), out.zone.value)
        else:
            d = Decision("allow", [], aids, _fmt(p), out.zone.value)
        return d, new_pres, new_sess


def _aware(at) -> bool:
    return isinstance(at, datetime) and at.tzinfo is not None and at.utcoffset() is not None


def _inputs_ok(subject, verb, resource, tokens, tool_calls, depth, influence, session, at) -> bool:
    if type(subject) is not str or not subject or len(subject) > 256 or not _SESSION_RE.match(subject):
        return False
    if C.action_problem(verb, resource):
        return False
    if any(type(x) is not int or not 0 <= x < 2 ** 53 for x in (tokens, tool_calls, depth)):
        return False
    if type(influence) is not str or influence not in C.INFLUENCE:
        return False
    if session is not None and (type(session) is not str or not _SESSION_RE.match(session)):
        return False
    return _aware(at)
