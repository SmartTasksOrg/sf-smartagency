"""Behaviour the conformance vectors do not cover: files, tampering on disk, fail-closed paths, plans,
audit records, the command line."""
import copy
import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone

import pytest

from sf_smartagency import AuditLog, Monitor, Registry, StatusLedger, LedgerError, canonical, contract as C, keys, to_syslog, verify_records
from sf_smartagency.cli import main
from sf_smartagency.registry import entry_for

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "spec", "tools"))
import make_vectors as mv  # noqa: E402

T = datetime(2026, 10, 26, 10, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def world(tmp_path):
    reg = Registry(mv.registry_data())
    led = StatusLedger(reg, str(tmp_path / "status.jsonl"))
    c = mv.base_contract()
    env = C.sign(c, mv.KA)
    led.record(mv.KA, "issue", c["id"], canonical.digest(c), "2026-10-26T09:00:00Z")
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    mon = Monitor(reg, led, audit, clock=lambda: T)
    assert mon.add_contract(env) == []
    return {"reg": reg, "led": led, "env": env, "mon": mon, "audit": audit, "tmp": tmp_path}


# ------------------------------------------------------------------ signing
def test_sign_refuses_a_key_that_is_not_the_issuer():
    with pytest.raises(ValueError, match="issuer"):
        C.sign(mv.base_contract(), mv.KB)


def test_sign_refuses_an_invalid_contract():
    with pytest.raises(ValueError, match="invalid contract"):
        C.sign(mv.base_contract(grants=[]), mv.KA)


def test_every_field_change_breaks_the_signature(world):
    env = world["env"]
    at = T
    for path, value in [(("subject",), "agent-2"), (("limits", "max_tokens"), 5), (("grants", 0, "effect"), "deny"),
                        (("expires",), "2027-06-01T00:00:00Z")]:
        e = copy.deepcopy(env)
        tgt = e["contract"]
        for p in path[:-1]:
            tgt = tgt[p]
        tgt[path[-1]] = value
        assert C.envelope_problems(e, lambda k: world["reg"].public_key(k, at)) == ["signature does not verify"]


def test_a_contract_with_a_changed_body_is_not_the_issued_one(world, tmp_path):
    """Even re-signed by the same issuer, a contract whose digest differs from the ledger's is not active."""
    c2 = copy.deepcopy(world["env"]["contract"])
    c2["limits"]["max_tokens"] = 99999
    mon = Monitor(world["reg"], world["led"], clock=lambda: T)
    assert mon.add_contract(C.sign(c2, mv.KA)) == []
    assert mon.check("agent-1", "query", "crm/a").reasons == ["no-active-contract"]


def test_loading_a_different_contract_under_a_used_id_is_refused(world):
    c2 = copy.deepcopy(world["env"]["contract"])
    c2["roles"] = ["other"]
    assert "already loaded" in world["mon"].add_contract(C.sign(c2, mv.KA))[0]


# ------------------------------------------------------------------ ledger files
def test_ledger_round_trips_through_its_file(world):
    again = StatusLedger(world["reg"], world["led"].path)
    assert again.entries == world["led"].entries
    assert again.status("ctr-1", T)["status"] == "active"


def test_an_edited_ledger_file_makes_the_monitor_deny_everything(world):
    p = world["led"].path
    with open(p, "rb") as f:
        data = f.read()
    with open(p, "wb") as f:
        f.write(data.replace(b'"issue"', b'"issue" ', 1))      # any byte change breaks the signature
    d = world["mon"].check("agent-1", "query", "crm/a")
    assert (d.outcome, d.reasons) == ("deny", ["ledger-invalid"])


def test_a_semantic_edit_to_the_ledger_file_is_detected(world):
    p = world["led"].path
    data = open(p, "rb").read()
    open(p, "wb").write(data.replace(b'"event":"issue"', b'"event":"suspend"', 1))
    assert world["mon"].check("agent-1", "query", "crm/a").reasons == ["ledger-invalid"]


def test_a_deleted_ledger_file_makes_the_monitor_deny_everything(world):
    os.unlink(world["led"].path)
    assert world["mon"].check("agent-1", "query", "crm/a").reasons == ["ledger-invalid"]


def test_a_revocation_appended_by_another_process_takes_effect(world):
    other = StatusLedger(world["reg"], world["led"].path)
    c = world["env"]["contract"]
    other.record(mv.KA, "revoke", c["id"], canonical.digest(c), "2026-10-26T09:30:00Z")
    assert world["mon"].check("agent-1", "query", "crm/a").reasons == ["no-active-contract"]


def test_only_the_issuer_can_change_a_contracts_status(world):
    c = world["env"]["contract"]
    with pytest.raises(LedgerError, match="only the contract's issuer"):
        world["led"].record(mv.KB, "revoke", c["id"], canonical.digest(c), "2026-10-26T09:30:00Z")


def test_a_refused_entry_leaves_the_file_unchanged(world):
    before = open(world["led"].path, "rb").read()
    c = world["env"]["contract"]
    with pytest.raises(LedgerError):
        world["led"].record(mv.KA, "resume", c["id"], canonical.digest(c), "2026-10-26T09:30:00Z")
    assert open(world["led"].path, "rb").read() == before


def test_a_stale_lock_file_is_reported(world):
    open(world["led"].path + ".lock", "w").close()
    c = world["env"]["contract"]
    with pytest.raises(LedgerError, match="held by another writer"):
        world["led"].record(mv.KA, "suspend", c["id"], canonical.digest(c), "2026-10-26T09:30:00Z")


# ------------------------------------------------------------------ monitor
def test_check_plan_changes_no_state(world):
    mon = world["mon"]
    steps = [{"verb": "query", "resource": "secrets/db"}, {"verb": "invoke", "resource": "net/upload"},
             {"verb": "invoke", "resource": "tools/search", "tool_calls": 3}, "not a step"]
    out = mon.check_plan("agent-1", steps)
    assert [d.outcome for d in out] == ["allow", "deny", "allow", "deny"]
    assert out[1].reasons == ["composite:no-exfiltration"] and out[3].reasons == ["invalid-action"]
    assert mon._pressure == {} and mon._sessions == {}
    assert mon.check("agent-1", "invoke", "net/upload").outcome == "allow"


def test_composite_sequences_are_caught_however_far_apart(world):
    mon = world["mon"]
    mon.check("agent-1", "query", "secrets/db", session="s")
    for _ in range(200):
        mon.check("agent-1", "query", "crm/a", session="s")
    assert mon.check("agent-1", "invoke", "net/upload", session="s").reasons == ["composite:no-exfiltration"]


def test_non_string_and_odd_inputs_are_denied_not_raised(world):
    mon = world["mon"]
    for args, kw in [((None, "query", "crm/a"), {}), (("agent-1", 7, "crm/a"), {}), (("agent-1", "query", None), {}),
                     (("agent-1", "query", "crm/a"), {"tokens": True}), (("agent-1", "query", "crm/a"), {"influence": "x"}),
                     (("agent-1", "query", "crm/\x1b[2J"), {}), (("agent-1", "*", "crm/a"), {})]:
        assert mon.check(*args, **kw).reasons == ["invalid-action"], (args, kw)


def test_every_decision_is_audited_in_a_verifiable_chain(world):
    mon = world["mon"]
    mon.check("agent-1", "query", "crm/a")
    mon.check("agent-1", "invoke", "tools/shell")
    mon.reset("agent-1")
    again = AuditLog(world["audit"].path)
    assert [r.get("outcome") for r in again.records] == ["allow", "deny", "reset"]
    recs = copy.deepcopy(again.records)
    recs[1]["outcome"] = "allow"
    with pytest.raises(ValueError, match="broken chain"):
        verify_records(recs)


def test_syslog_line(world):
    world["mon"].check("agent-1", "invoke", "tools/shell")
    line = to_syslog(world["audit"].records[-1], host="h1")
    assert line.startswith("<109>1 2026-10-26T10:00:00Z h1 sf-smartagency - deny - {")
    assert "\n" not in line


def test_expired_issuer_key_window(world):
    data = mv.registry_data()
    data["keys"][0]["not_after"] = "2026-10-26T09:59:00Z"
    reg = Registry(data)
    mon = Monitor(reg, StatusLedger(reg), clock=lambda: T)
    assert "not trusted" in mon.add_contract(world["env"])[0]


# ------------------------------------------------------------------ registry
@pytest.mark.parametrize("mutate,msg", [
    (lambda e: e.update({"kid": "ed25519:" + "0" * 32}), "kid does not match"),
    (lambda e: e.update({"public_key": "!!"}), "public_key"),
    (lambda e: e.update({"extra": 1}), "unknown fields"),
    (lambda e: e.update({"not_after": "2025-01-01T00:00:00Z"}), "not_after must be later"),
])
def test_registry_rejects_bad_entries(mutate, msg):
    data = mv.registry_data()
    mutate(data["keys"][0])
    with pytest.raises(ValueError, match=msg):
        Registry(data)


# ------------------------------------------------------------------ command line
def test_cli_end_to_end(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(["keygen", "--out", "issuer.pem", "--name", "test issuer"]) == 0
    entry = json.loads(capsys.readouterr().out)
    if os.name == "posix":
        assert stat.S_IMODE(os.stat("issuer.pem").st_mode) == 0o600
    assert main(["keygen", "--out", "issuer.pem", "--name", "x"]) == 2         # never overwrites a key
    entry["not_before"] = "2026-01-01T00:00:00Z"
    (tmp_path / "registry.json").write_text(json.dumps({"schema": "smartagency.registry/1", "keys": [entry]}))
    c = mv.base_contract(issuer=entry["kid"])
    (tmp_path / "contract.json").write_text(json.dumps(c))
    assert main(["validate", "contract.json"]) == 0
    assert main(["sign", "contract.json", "--key", "issuer.pem", "--out", "contract.signed.json"]) == 0
    assert main(["sign", "contract.json", "--key", "issuer.pem", "--out", "contract.signed.json"]) == 2
    assert main(["verify", "contract.signed.json", "--registry", "registry.json"]) == 0
    base = ["--ledger", "status.jsonl", "--registry", "registry.json"]
    assert main(["ledger", "issue", *base, "--key", "issuer.pem", "--contract", "contract.signed.json",
                 "--at", "2026-10-26T09:00:00Z"]) == 0
    chk = ["check", *base, "--contracts", "contract.signed.json", "--subject", "agent-1", "--at", "2026-10-26T10:00:00Z",
           "--audit", "audit.jsonl"]
    capsys.readouterr()
    assert main([*chk, "--verb", "query", "--resource", "crm/a"]) == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "allow"
    assert main([*chk, "--verb", "invoke", "--resource", "tools/shell"]) == 1
    assert main(["ledger", "revoke-grants", *base, "--key", "issuer.pem", "--contract", "contract.signed.json",
                 "--grants", "0", "--at", "2026-10-26T09:30:00Z"]) == 0
    assert main([*chk, "--verb", "query", "--resource", "crm/a"]) == 1
    assert main(["ledger", "verify", *base]) == 0
    assert main(["status", *base, "--id", "ctr-1"]) == 0
    assert len(AuditLog(str(tmp_path / "audit.jsonl")).records) == 3
    capsys.readouterr()
    assert main(["ledger", "resume", *base, "--key", "issuer.pem", "--contract", "contract.signed.json"]) == 2
    assert "refused" in capsys.readouterr().err


def test_cli_unreadable_files_exit_2_without_a_traceback(tmp_path, capsys):
    (tmp_path / "bad.json").write_bytes(b"\xff\xfe")
    assert main(["validate", str(tmp_path / "bad.json")]) == 2
    assert main(["validate", str(tmp_path / "missing.json")]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err


def test_cli_escapes_control_characters_in_problems(tmp_path, capsys):
    c = mv.base_contract(id="ctr\x1b[2J")
    (tmp_path / "c.json").write_text(json.dumps(c))
    assert main(["validate", str(tmp_path / "c.json")]) == 1
    assert "\x1b" not in capsys.readouterr().out


def test_demo_and_bundled_vectors(capsys):
    assert main(["demo"]) == 0
    assert capsys.readouterr().out.rstrip().endswith("demo OK")
    assert main(["vectors"]) == 0
