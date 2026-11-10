"""`sf-smartagency demo`: one agent, one contract, every kind of decision. In memory, no network, fixed clock.

The issuer key comes from a fixed seed so the output is the same on every run. That is for the demo only:
a real issuer key comes from `sf-smartagency keygen` and never leaves its owner.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from . import contract as C, keys
from .audit import AuditLog, verify_records
from .canonical import digest
from .ledger import StatusLedger
from .monitor import Monitor
from .registry import Registry, entry_for

AGENT = "iaiso://agent/research-1"
T0 = datetime(2026, 10, 26, 9, 0, 0, tzinfo=timezone.utc)


def demo_key():
    return keys.from_seed(bytes(range(32)))          # demo only: a fixed, public seed


def demo_contract(issuer_kid: str) -> dict:
    return {
        "schema": C.SCHEMA_ID, "id": "ctr-research-1", "version": "1.0.0", "issuer": issuer_kid,
        "subject": AGENT, "roles": ["researcher"],
        "grants": [
            {"verb": "query", "resource": "crm/**", "effect": "allow"},
            {"verb": "query", "resource": "secrets/**", "effect": "allow"},
            {"verb": "invoke", "resource": "tools/search", "effect": "allow"},
            {"verb": "invoke", "resource": "net/**", "effect": "allow"},
            {"verb": "invoke", "resource": "tools/shell", "effect": "deny"},
        ],
        "limits": {"max_tokens": 4000, "max_tool_calls": 3, "max_depth": 2, "max_influence": "informational",
                   "pressure": {"escalation_threshold": "0.85", "release_threshold": "0.95"}},
        "composite": [{"name": "no-exfiltration", "deny_sequence": [
            {"verb": "query", "resource": "secrets/**"}, {"verb": "invoke", "resource": "net/**"}]}],
        "not_before": "2026-10-26T00:00:00Z", "expires": "2027-01-01T00:00:00Z",
    }


def run(out=print) -> int:
    key = demo_key()
    reg = Registry({"schema": "smartagency.registry/1",
                    "keys": [entry_for(key, "demo issuer (fixed seed: never use for real)", "2026-01-01T00:00:00Z")]})
    ledger = StatusLedger(reg)
    audit = AuditLog()
    now = [T0]
    mon = Monitor(reg, ledger, audit, clock=lambda: now[0])
    env = C.sign(demo_contract(keys.key_id(key.public_key())), key)
    problems = mon.add_contract(env)
    assert not problems, problems
    ledger.record(key, "issue", env["contract"]["id"], digest(env["contract"]), T0)
    out(f"SmartAgency demo: contract {env['contract']['id']} for {AGENT}, signed by {env['signature']['kid']}")
    out("")

    def act(label, verb, resource, **kw):
        now[0] += timedelta(seconds=1)
        d = mon.check(AGENT, verb, resource, **kw)
        out(f"  {d.outcome:<9} {verb:<6} {resource:<20} {label:<44} {', '.join(d.reasons) or '-'}"
            f"  (pressure {d.pressure}, {d.zone})")
        return d

    out("  outcome   verb   resource             what                                         reasons")
    act("read a CRM record", "query", "crm/accounts/42", tokens=800, session="s1")
    act("a tool the contract denies", "invoke", "tools/shell", tool_calls=1, session="s1")
    act("read a secret", "query", "secrets/vault/db", tokens=200, session="s1")
    act("then send to the network: exfiltration", "invoke", "net/upload", tool_calls=1, session="s1")
    act("network in a clean session", "invoke", "net/search", tool_calls=1, session="s2")
    act("over the token limit", "invoke", "tools/search", tokens=9000, tool_calls=1)
    act("more influence than allowed", "invoke", "tools/search", tool_calls=1, influence="persuasive")
    out("")
    out("  heavy tool use, until SmartFabric pressure escalates and then releases:")
    for i in range(12):
        d = act(f"tool burst {i + 1}", "invoke", "tools/search", tokens=1000, tool_calls=1, depth=1)
        if "pressure-release" in d.reasons:
            break
    act("after the release", "query", "crm/accounts/42")
    mon.reset(AGENT)
    act("after a person's reset", "query", "crm/accounts/42")
    out("")
    now[0] += timedelta(seconds=1)
    ledger.record(key, "revoke", env["contract"]["id"], digest(env["contract"]), now[0], reason="demo: revoked")
    act("after the contract is revoked", "query", "crm/accounts/42")
    out("")
    verify_records(audit.records)
    ledger.verify()
    out(f"audit log: {len(audit.records)} hash-chained records, chain verified")
    out(f"status ledger: {len(ledger.entries)} signed entries, chain verified")
    out("demo OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
