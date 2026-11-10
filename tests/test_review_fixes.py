"""Regression tests for the pre-release review findings (CHANGELOG, "Fixed before release")."""
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

import pytest

from sf_smartagency import AuditLog, LedgerError, Monitor, Registry, StatusLedger, canonical, contract as C, keys
from sf_smartagency.cli import main

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "spec", "tools"))
import make_vectors as mv  # noqa: E402

T = datetime(2026, 10, 26, 10, 0, 0, tzinfo=timezone.utc)


def world(tmp_path, audit=True, contract=None):
    reg = Registry(mv.registry_data())
    led = StatusLedger(reg, str(tmp_path / "status.jsonl"))
    c = contract or mv.base_contract()
    led.record(mv.KA, "issue", c["id"], canonical.digest(c), "2026-10-26T09:00:00Z")
    mon = Monitor(reg, led, AuditLog(str(tmp_path / "audit.jsonl")) if audit else None, clock=lambda: T)
    assert mon.add_contract(C.sign(c, mv.KA)) == []
    return reg, led, mon, c


# H1: a ledger rolled back to an older valid copy must not bring a revoked contract back
def test_rollback_is_detected_by_a_running_monitor_and_by_an_anchor(tmp_path):
    reg, led, mon, c = world(tmp_path)
    old = tmp_path / "old.jsonl"
    shutil.copy(led.path, old)
    led.record(mv.KA, "revoke", c["id"], canonical.digest(c), "2026-10-26T09:30:00Z")
    head = led.head()
    assert mon.check("agent-1", "query", "crm/a").reasons == ["no-active-contract"]
    shutil.copy(old, led.path)
    assert mon.check("agent-1", "query", "crm/a").reasons == ["ledger-invalid"]
    with pytest.raises(LedgerError, match="anchor"):
        StatusLedger(reg, led.path, anchor=head)                 # a fresh process with the anchor
    assert StatusLedger(reg, led.path).status(c["id"], T)["status"] == "active"   # without it: undetectable


def test_a_truncated_ledger_file_is_detected(tmp_path):
    reg, led, mon, c = world(tmp_path)
    led.record(mv.KA, "suspend", c["id"], canonical.digest(c), "2026-10-26T09:30:00Z")
    data = open(led.path, "rb").read()
    open(led.path, "wb").write(data[: data.index(b"\n") + 1])
    assert mon.check("agent-1", "query", "crm/a").reasons == ["ledger-invalid"]


def test_record_refuses_to_restart_a_deleted_ledger(tmp_path):
    reg, led, mon, c = world(tmp_path)
    os.unlink(led.path)
    with pytest.raises(LedgerError, match="disappeared"):
        led.record(mv.KA, "revoke", c["id"], canonical.digest(c), "2026-10-26T09:30:00Z")


# M2 / M3: check_plan keeps to itself; malformed sessions and times are refused before any state changes
def test_check_plan_does_not_touch_real_sessions(tmp_path):
    _, _, mon, _ = world(tmp_path)
    mon.check("agent-1", "query", "secrets/db", session="plan")
    mon.check_plan("agent-1", [])
    assert mon.check("agent-1", "invoke", "net/upload", session="plan").reasons == ["composite:no-exfiltration"]


@pytest.mark.parametrize("kw", [{"session": 1.5}, {"session": []}, {"session": "a\x00b"}, {"session": "x" * 300},
                                {"at": datetime(2026, 10, 26, 10)}, {"tokens": 2 ** 60}])
def test_malformed_inputs_change_nothing_and_are_audited(tmp_path, kw):
    _, _, mon, _ = world(tmp_path)
    d = mon.check("agent-1", "invoke", "tools/search", tool_calls=3, **kw)
    assert d.reasons == ["invalid-action"]
    assert mon._pressure == {} and mon._sessions == {}
    assert mon.audit.records[-1]["reasons"] == ["invalid-action"]


@pytest.mark.parametrize("steps", [None, "x", [None], [{"verb": 1}]])
def test_check_plan_never_raises(tmp_path, steps):
    _, _, mon, _ = world(tmp_path)
    assert all(d.reasons == ["invalid-action"] for d in mon.check_plan("agent-1", steps))


def test_an_unwritable_audit_log_denies_without_changing_state(tmp_path):
    _, _, mon, _ = world(tmp_path)
    open(mon.audit.path + ".lock", "w").close()                 # held by a writer that never finishes
    d = mon.check("agent-1", "invoke", "tools/search", tool_calls=3)
    assert d.reasons == ["audit-unavailable"] and mon._pressure == {}


# M4: deeply nested JSON fails closed instead of raising
def test_deeply_nested_lines_fail_closed(tmp_path):
    reg, led, mon, c = world(tmp_path)
    with open(led.path, "ab") as f:
        f.write(b"[" * 100000 + b"]" * 100000 + b"\n")
    assert mon.check("agent-1", "query", "crm/a").reasons == ["ledger-invalid"]
    deep = tmp_path / "deep.json"
    deep.write_bytes(b"[" * 100000 + b"]" * 100000)
    assert main(["validate", str(deep)]) == 2


# M5: actions are not normalised, so variants that a host might normalise are refused
@pytest.mark.parametrize("verb,resource", [
    ("query", "files/public/../secrets/k"), ("query", "files/./secrets/k"), ("query", "files/secrets%2Fk"),
    ("query", "files\\\\secrets"), ("x-acme-DELETE", "tools/db"), ("x-acme-delete ", "tools/db"),
    ("x-acme-delete​", "tools/db"), ("x-", "tools/db"), ("x-\x1b[2J", "tools/db")])
def test_ambiguous_actions_are_invalid(tmp_path, verb, resource):
    _, _, mon, _ = world(tmp_path, audit=False)
    assert mon.check("agent-1", verb, resource).reasons == ["invalid-action"]


def test_str_subclasses_are_refused(tmp_path):
    class Sneaky(str):
        def split(self, *a):
            return ["crm", "a"]
    _, _, mon, _ = world(tmp_path, audit=False)
    assert mon.check("agent-1", "query", Sneaky("secrets/x")).reasons == ["invalid-action"]


def test_grants_with_dot_segments_or_escapes_are_invalid():
    for r in ("files/../x", "files/./x", "a%2Fb", "a/**/**/**/**/**/x"):
        c = mv.base_contract()
        c["grants"].append({"verb": "query", "resource": r, "effect": "deny"})
        assert C.validate(c), r


# M6: matching is polynomial
def test_wildcard_matching_is_fast():
    t = time.perf_counter()
    assert not C.resource_matches("**/**/**/**/z", "/".join(["a"] * 256))
    assert time.perf_counter() - t < 0.5


# L1: the one-shot check command has no session option
def test_cli_check_has_no_session_option(capsys):
    with pytest.raises(SystemExit) as e:
        main(["check", "--registry", "r", "--ledger", "l", "--contracts", "c", "--subject", "s", "--verb", "query",
              "--resource", "x", "--session", "s1"])
    assert e.value.code == 2


# L2: concurrent writers keep the audit chain intact
def test_concurrent_audit_writers(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    code = ("import sys; from sf_smartagency import AuditLog\n"
            "a = AuditLog(sys.argv[1])\n"
            "for i in range(10): a.append({'outcome': 'allow', 'n': i})\n")
    procs = [subprocess.Popen([sys.executable, "-c", code, path]) for _ in range(6)]
    assert all(p.wait(60) == 0 for p in procs)
    assert len(AuditLog(path).records) == 60


# L3: zones follow the contract's thresholds, also on denies
def test_zone_uses_the_contracts_thresholds(tmp_path):
    c = mv.base_contract(limits={"max_tokens": 4000, "max_tool_calls": 3, "max_depth": 2, "max_influence": "informational",
                                 "pressure": {"escalation_threshold": "0.3", "release_threshold": "0.9"}})
    _, _, mon, _ = world(tmp_path, audit=False, contract=c)
    mon.check("agent-1", "invoke", "tools/search", tool_calls=3)
    d1 = mon.check("agent-1", "invoke", "tools/search", tool_calls=3)
    d2 = mon.check("agent-1", "invoke", "tools/shell")
    assert (d1.zone, d2.zone, d2.pressure) == ("escalation", "escalation", d1.pressure)


# L4: one encoding per value
def test_non_canonical_signature_strings_are_invalid():
    sig = keys.sign(mv.KA, b"m")
    assert keys.verify(mv.KA.public_key(), b"m", sig)
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_":
        if c != sig[-1]:                       # the last character carries 2 unused bits
            assert not keys.verify(mv.KA.public_key(), b"m", sig[:-1] + c)


@pytest.mark.parametrize("bad", ["2026-10-26T9:0:0Z", "2026-1-1T00:00:00Z", "2026-10-26T09:00:00+00:00", "2026-10-26 09:00:00Z"])
def test_times_must_be_exact(bad):
    with pytest.raises(ValueError):
        C.parse_time(bad)


def test_ledger_lines_must_end_with_exactly_one_newline(tmp_path):
    reg, led, mon, c = world(tmp_path, audit=False)
    data = open(led.path, "rb").read()
    open(led.path, "wb").write(data.replace(b"\n", b"\r\n"))
    with pytest.raises(LedgerError, match="canonical"):
        StatusLedger(reg, led.path)
    open(led.path, "wb").write(data.rstrip(b"\n"))
    with pytest.raises(LedgerError, match="no newline"):
        StatusLedger(reg, led.path)


# L5: a missing ledger is an error for verify, status and check
def test_cli_missing_ledger_is_an_error(tmp_path, capsys):
    (tmp_path / "reg.json").write_text(json.dumps(mv.registry_data()))
    base = ["--ledger", str(tmp_path / "typo.jsonl"), "--registry", str(tmp_path / "reg.json")]
    assert main(["ledger", "verify", *base]) == 2
    assert main(["status", *base, "--id", "ctr-1"]) == 2


# audit records signed by the monitor
def test_signed_audit_records(tmp_path):
    from sf_smartagency import record_signed_by
    mkey = keys.from_seed(bytes(range(64, 96)))
    mreg = Registry({"schema": "smartagency.registry/1", "keys": [
        __import__("sf_smartagency.registry", fromlist=["entry_for"]).entry_for(mkey, "monitor", "2026-01-01T00:00:00Z")]})
    reg = Registry(mv.registry_data())
    led = StatusLedger(reg)
    c = mv.base_contract()
    led.record(mv.KA, "issue", c["id"], canonical.digest(c), "2026-10-26T09:00:00Z")
    audit = AuditLog(str(tmp_path / "a.jsonl"), signer=mkey)
    mon = Monitor(reg, led, audit, clock=lambda: T)
    mon.add_contract(C.sign(c, mv.KA))
    mon.check("agent-1", "query", "crm/a")
    rec = AuditLog(str(tmp_path / "a.jsonl")).records[-1]
    assert record_signed_by(rec, mreg)
    assert not record_signed_by({**rec, "outcome": "deny"}, mreg)
    assert not record_signed_by({k: v for k, v in rec.items() if k != "sig"}, mreg)
    assert not record_signed_by(rec, reg)                       # not a monitor key


# second review round
def test_composite_progress_survives_supersession_and_suspension(tmp_path):
    reg, led, mon, c = world(tmp_path, audit=False)
    mon.check("agent-1", "query", "secrets/db", session="s")
    c2 = mv.base_contract(id="ctr-2", supersedes="ctr-1")
    led.record(mv.KA, "issue", "ctr-2", canonical.digest(c2), "2026-10-26T09:30:00Z", supersedes="ctr-1")
    assert mon.add_contract(C.sign(c2, mv.KA)) == []
    assert mon.check("agent-1", "invoke", "net/upload", session="s").reasons == ["composite:no-exfiltration"]


def test_rules_of_a_suspended_contract_keep_counting(tmp_path):
    reg = Registry(mv.registry_data())
    led = StatusLedger(reg)
    plain = mv.base_contract(id="ctr-plain", composite=[])
    rules = mv.base_contract(id="ctr-rules")
    for x in (plain, rules):
        led.record(mv.KA, "issue", x["id"], canonical.digest(x), "2026-10-26T09:00:00Z")
    led.record(mv.KA, "suspend", "ctr-rules", canonical.digest(rules), "2026-10-26T09:10:00Z")
    now = [T]
    mon = Monitor(reg, led, clock=lambda: now[0])
    for x in (plain, rules):
        assert mon.add_contract(C.sign(x, mv.KA)) == []
    assert mon.check("agent-1", "query", "secrets/db", session="s").outcome == "allow"   # allowed by ctr-plain
    led.record(mv.KA, "resume", "ctr-rules", canonical.digest(rules), "2026-10-26T10:00:00Z")
    now[0] = T.replace(minute=5)
    assert mon.check("agent-1", "invoke", "net/upload", session="s").reasons == ["composite:no-exfiltration"]


def test_a_monitor_key_cannot_be_an_issuer_key(tmp_path):
    reg = Registry(mv.registry_data())
    with pytest.raises(ValueError, match="issuer key"):
        Monitor(reg, StatusLedger(reg), AuditLog(signer=mv.KA))


@pytest.mark.parametrize("verb,resource", [("x-acme-delete.", "tools/db"), ("x-acme-delete-", "tools/db"),
                                           ("x-acme--delete", "tools/db"), ("query", "files/secrets;x/k"),
                                           ("query", "files/a,b"), ("query", "files/a b")])
def test_stricter_verbs_and_resources(tmp_path, verb, resource):
    _, _, mon, _ = world(tmp_path, audit=False)
    assert mon.check("agent-1", verb, resource).reasons == ["invalid-action"]


def test_audit_edge_cases(tmp_path):
    _, _, mon, _ = world(tmp_path)
    mon.check("agent-1", "query", "crm/a", at=datetime(2026, 10, 26, 10))          # naive time: invalid
    assert isinstance(mon.audit.records[-1]["at"], str)
    os.unlink(mon.audit.path)
    assert mon.check("agent-1", "query", "crm/a").reasons == ["audit-unavailable"]
    with pytest.raises(LedgerError, match="anchor"):
        StatusLedger(Registry(mv.registry_data()), anchor=1)


# Pre-release: an engine that keeps its state somewhere else must not make every step start from zero
def test_an_incompatible_smartfabric_is_refused(tmp_path, monkeypatch):
    from sf_smartfabric import PressureEngine
    from sf_smartagency import PressureStateError
    from sf_smartagency import monitor as M

    class Renamed(PressureEngine):          # a SmartFabric that stores pressure under another name
        @property
        def pressure(self):
            return getattr(self, "_value", 0.0)

        def step(self, **kw):               # it steps from its own field, whatever _p says
            self._p = self.pressure
            out = super().step(**kw)
            self._value = self._p
            return out

    (tmp_path / "new").mkdir()
    _, _, mon, _ = world(tmp_path)
    monkeypatch.setattr(M, "PressureEngine", Renamed)
    with pytest.raises(PressureStateError):                         # a new monitor refuses to start
        world(tmp_path / "new")
    mon.check("agent-1", "invoke", "tools/search", tool_calls=1)    # from zero, zero reads back as zero
    with pytest.raises(PressureStateError):                         # the next step would have restarted at zero
        mon.check("agent-1", "invoke", "tools/search", tool_calls=1)


def test_the_installed_smartfabric_carries_state():
    from sf_smartagency import monitor as M
    M._check_engine()
    eng = M._engine(M.PressureConfig(), 0.4, False)
    assert eng.step(tool_calls=1).pressure > 0.4
