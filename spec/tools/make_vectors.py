#!/usr/bin/env python3
"""Generate spec/conformance/*.json from the Python reference.

    python spec/tools/make_vectors.py            # write the files (and the copies bundled in the package)
    python spec/tools/make_vectors.py --check    # exit 1 if a file differs from what would be written

Keys come from fixed seeds (Ed25519 signatures are deterministic), so the vectors never change unless the
behaviour does.
"""
from __future__ import annotations

import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src"))

from sf_smartagency import canonical, contract as C, keys  # noqa: E402
from sf_smartagency.ledger import LedgerError, StatusLedger  # noqa: E402
from sf_smartagency.monitor import Monitor  # noqa: E402
from sf_smartagency.registry import Registry, entry_for  # noqa: E402

OUT = os.path.join(ROOT, "spec", "conformance")
BUNDLED = os.path.join(ROOT, "src", "sf_smartagency", "data", "conformance")
CHECK = "--check" in sys.argv
DIFF: list[str] = []
SEED_A, SEED_B = bytes(range(32)), bytes(range(32, 64))
KA, KB = keys.from_seed(SEED_A), keys.from_seed(SEED_B)
KIDA, KIDB = keys.key_id(KA.public_key()), keys.key_id(KB.public_key())


def write(name: str, obj) -> None:
    text = json.dumps(obj, indent=1, ensure_ascii=False, sort_keys=True) + "\n"
    for d in (OUT, BUNDLED):
        p = os.path.join(d, name)
        if CHECK:
            old = open(p, encoding="utf-8").read() if os.path.exists(p) else None
            if old != text:
                DIFF.append(os.path.relpath(p, ROOT))
        else:
            os.makedirs(d, exist_ok=True)
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)


def registry_data():
    return {"schema": "smartagency.registry/1", "keys": [
        entry_for(KA, "issuer A", "2026-01-01T00:00:00Z"),
        {**entry_for(KB, "issuer B", "2026-01-01T00:00:00Z"), "revoked_at": "2026-11-01T00:00:00Z"}]}


def base_contract(**kw):
    c = {"schema": C.SCHEMA_ID, "id": "ctr-1", "version": "1.0.0", "issuer": KIDA, "subject": "agent-1",
         "roles": ["analyst"],
         "grants": [{"verb": "query", "resource": "crm/**", "effect": "allow"},
                    {"verb": "invoke", "resource": "tools/*", "effect": "allow"},
                    {"verb": "invoke", "resource": "tools/shell", "effect": "deny"},
                    {"verb": "query", "resource": "secrets/*", "effect": "allow"},
                    {"verb": "invoke", "resource": "net/**", "effect": "allow"}],
         "limits": {"max_tokens": 4000, "max_tool_calls": 3, "max_depth": 2, "max_influence": "informational"},
         "composite": [{"name": "no-exfiltration", "deny_sequence": [
             {"verb": "query", "resource": "secrets/*"}, {"verb": "invoke", "resource": "net/**"}]}],
         "not_before": "2026-10-01T00:00:00Z", "expires": "2027-01-01T00:00:00Z"}
    c.update(kw)
    return c


# ---------------------------------------------------------------------------- canonical + keys
def canonical_vectors():
    inputs = [{"b": 1, "a": [True, None, "x"]}, {"é": "ü", "a": {"z": 0, "y": -5}}, [], "line\nbreak ",
              {"n": 9007199254740991}]
    cases = [{"input": i, "canonical": canonical.encode(i).decode("utf-8"), "digest": canonical.digest(i)} for i in inputs]
    refused = [{"name": "float", "input": {"x": 1.5}}, {"name": "integer too large", "input": {"n": 9007199254740992}}]
    return {"description": "canonical(input) and digest(input); refused inputs raise", "cases": cases, "refused": refused}


def _same_bytes_variant(sig: str) -> str:
    """A different base64url string that a lax decoder maps to the same 64 bytes."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    i = alphabet.index(sig[-1])
    v = sig[:-1] + alphabet[i ^ 1]
    import base64
    assert base64.urlsafe_b64decode(v + "==") == base64.urlsafe_b64decode(sig + "==") and v != sig
    return v


def key_vectors():
    msg = b"smartagency"
    cases = []
    for seed in (SEED_A, SEED_B):
        k = keys.from_seed(seed)
        pub = k.public_key()
        cases.append({"seed_hex": seed.hex(), "public_key": keys.b64e(keys.public_raw(pub)), "kid": keys.key_id(pub),
                      "message_hex": msg.hex(), "signature": keys.sign(k, msg)})
    sig = cases[0]["signature"]
    verify = [
        {"name": "valid", "public_key": cases[0]["public_key"], "message_hex": msg.hex(), "signature": sig, "valid": True},
        {"name": "other message", "public_key": cases[0]["public_key"], "message_hex": b"smartagencY".hex(), "signature": sig, "valid": False},
        {"name": "other key", "public_key": cases[1]["public_key"], "message_hex": msg.hex(), "signature": sig, "valid": False},
        {"name": "truncated signature", "public_key": cases[0]["public_key"], "message_hex": msg.hex(), "signature": sig[:-4], "valid": False},
        {"name": "padding in signature", "public_key": cases[0]["public_key"], "message_hex": msg.hex(), "signature": sig + "==", "valid": False},
        {"name": "unused bits set in the last character", "public_key": cases[0]["public_key"], "message_hex": msg.hex(),
         "signature": _same_bytes_variant(sig), "valid": False},
    ]
    return {"description": "Ed25519 from 32-byte seeds: public key, kid, deterministic signature; verify cases",
            "keys": cases, "verify": verify}


# ---------------------------------------------------------------------------- contracts
def contract_vectors():
    def mk(name, f):
        c = base_contract()
        f(c)
        return {"name": name, "contract": c, "valid": not C.validate(c)}

    def drop(k):
        return lambda c: c.pop(k)

    cases = [
        mk("valid", lambda c: None),
        mk("missing expires", drop("expires")),
        mk("unknown top-level field", lambda c: c.update({"extra": 1})),
        mk("unknown verb", lambda c: c["grants"].append({"verb": "teleport", "resource": "x", "effect": "allow"})),
        mk("extension verb", lambda c: c["grants"].append({"verb": "x-acme-ping", "resource": "x", "effect": "allow"})),
        mk("wildcard inside a segment", lambda c: c["grants"].append({"verb": "query", "resource": "crm/acc*", "effect": "allow"})),
        mk("empty path segment", lambda c: c["grants"].append({"verb": "query", "resource": "crm//x", "effect": "allow"})),
        mk("expires before not_before", lambda c: c.update({"expires": "2026-09-01T00:00:00Z"})),
        mk("bad time format", lambda c: c.update({"expires": "2027-01-01 00:00:00"})),
        mk("float limit", lambda c: c["limits"].update({"max_tokens": 1.5})),
        mk("pressure release below escalation", lambda c: c["limits"].update({"pressure": {"escalation_threshold": "0.9", "release_threshold": "0.8"}})),
        mk("pressure as a number", lambda c: c["limits"].update({"pressure": {"escalation_threshold": 0.8}})),
        mk("duplicate composite names", lambda c: c["composite"].append(copy.deepcopy(c["composite"][0]))),
        mk("composite of one step", lambda c: c["composite"][0].update({"deny_sequence": c["composite"][0]["deny_sequence"][:1]})),
        mk("supersedes itself", lambda c: c.update({"supersedes": "ctr-1"})),
        mk("issuer not an ed25519 kid", lambda c: c.update({"issuer": "rsa:abc"})),
        mk("bad version", lambda c: c.update({"version": "1.0"})),
        mk("no grants", lambda c: c.update({"grants": []})),
        mk("dot-dot segment in a grant", lambda c: c["grants"].append({"verb": "query", "resource": "crm/../hr", "effect": "deny"})),
        mk("percent escape in a grant", lambda c: c["grants"].append({"verb": "query", "resource": "crm%2Fhr", "effect": "deny"})),
        mk("five ** segments", lambda c: c["grants"].append({"verb": "query", "resource": "**/**/**/**/**", "effect": "deny"})),
        mk("time without zero padding", lambda c: c.update({"expires": "2027-1-1T00:00:00Z"})),
    ]
    env = C.sign(base_contract(), KA)
    tampered = copy.deepcopy(env)
    tampered["contract"]["limits"]["max_tokens"] = 400000
    wrong_kid = copy.deepcopy(env)
    wrong_kid["signature"]["kid"] = KIDB
    envelopes = [
        {"name": "valid", "envelope": env, "valid": True},
        {"name": "contract changed after signing", "envelope": tampered, "valid": False},
        {"name": "kid differs from issuer", "envelope": wrong_kid, "valid": False},
        {"name": "other algorithm", "envelope": {**env, "signature": {**env["signature"], "alg": "rsa-pss"}}, "valid": False},
        {"name": "extra envelope field", "envelope": {**env, "note": "x"}, "valid": False},
    ]
    reg = Registry(registry_data())
    at = C.parse_time("2026-10-26T00:00:00Z")
    for e in envelopes:
        assert (not C.envelope_problems(e["envelope"], lambda k: reg.public_key(k, at))) == e["valid"], e["name"]
    match = [(p, r, C.resource_matches(p, r)) for p, r in [
        ("crm/**", "crm"), ("crm/**", "crm/a/b/c"), ("crm/*", "crm/a"), ("crm/*", "crm/a/b"), ("crm/*", "crm"),
        ("**", "anything/at/all"), ("a/**/z", "a/z"), ("a/**/z", "a/b/c/z"), ("a/**/z", "a/b/c"), ("a/*/c", "a/b/c"),
        ("a/b", "a/b"), ("a/b", "a/B"), ("*", "a"), ("*", "a/b")]]
    return {"description": "contract validity, envelope verification at 2026-10-26T00:00:00Z with the registry, resource matching",
            "registry": registry_data(), "verify_at": "2026-10-26T00:00:00Z", "contracts": cases, "envelopes": envelopes,
            "resource_matches": [{"pattern": p, "resource": r, "matches": m} for p, r, m in match]}


# ---------------------------------------------------------------------------- ledger
def ledger_vectors():
    reg = Registry(registry_data())
    c1 = base_contract()
    d1 = canonical.digest(c1)
    good = StatusLedger(reg)
    good.record(KA, "issue", "ctr-1", d1, "2026-10-26T09:00:00Z")
    good.record(KA, "revoke_grants", "ctr-1", d1, "2026-10-26T09:01:00Z", grants=[1])
    good.record(KA, "suspend", "ctr-1", d1, "2026-10-26T09:02:00Z", reason="incident 7")
    good.record(KA, "resume", "ctr-1", d1, "2026-10-26T09:03:00Z")
    c2 = base_contract(id="ctr-2", supersedes="ctr-1")
    good.record(KA, "issue", "ctr-2", canonical.digest(c2), "2026-10-26T09:04:00Z", supersedes="ctr-1")
    good.record(KA, "revoke", "ctr-2", canonical.digest(c2), "2026-10-26T09:05:00Z")
    entries = good.entries
    statuses = [{"id": i, "at": t, "status": good.status(i, C.parse_time(t))} for i, t in [
        ("ctr-1", "2026-10-26T08:59:59Z"), ("ctr-1", "2026-10-26T09:00:00Z"), ("ctr-1", "2026-10-26T09:02:30Z"),
        ("ctr-1", "2026-10-26T09:03:00Z"), ("ctr-1", "2026-10-26T09:10:00Z"), ("ctr-2", "2026-10-26T09:10:00Z"),
        ("ctr-9", "2026-10-26T09:10:00Z")]]

    def bad(name, mutate):
        es = copy.deepcopy(entries)
        mutate(es)
        led = StatusLedger(reg)
        try:
            for e in es:
                led.append(e)
            ok = True
        except LedgerError:
            ok = False
        assert not ok, name
        return {"name": name, "entries": es, "valid": False}

    def resign(es, i, **kw):
        es[i].update(kw)
        body = {k: v for k, v in es[i].items() if k != "sig"}
        es[i]["sig"] = keys.sign(KA, canonical.encode(body))

    def resign_chain(es, start):
        for i in range(start, len(es)):
            if i > 0:
                es[i]["prev"] = canonical.digest(es[i - 1])
            es[i]["seq"] = i
            resign(es, i)

    invalid = [
        bad("entry removed", lambda es: es.pop(2)),
        bad("entries reordered", lambda es: es.insert(1, es.pop(2))),
        bad("reason edited", lambda es: es[2].update({"reason": "nothing happened"})),
        bad("re-signed edit without fixing the chain", lambda es: resign(es, 1, grants=[1, 2])),
        bad("event after revoke", lambda es: (es.append(copy.deepcopy(es[5])), resign_chain(es, 6))),
        bad("issued twice", lambda es: (es.insert(1, copy.deepcopy(es[0])), resign_chain(es, 1))),
        bad("resume without suspend", lambda es: (es.pop(2), resign_chain(es, 2))),
        bad("time goes backwards", lambda es: (resign(es, 1, at="2026-10-26T08:00:00Z"), resign_chain(es, 2))),
        bad("signed by a key the registry does not hold",
            lambda es: es.__setitem__(0, {**es[0], "sig": keys.sign(keys.from_seed(bytes(32)),
                                                                     canonical.encode({k: v for k, v in es[0].items() if k != "sig"}))})),
    ]
    return {"description": "a valid ledger and its statuses; invalid ledgers (append each entry in order; one must fail)",
            "registry": registry_data(), "valid": {"entries": entries, "statuses": statuses}, "invalid": invalid}


# ---------------------------------------------------------------------------- decisions
def decision_vectors():
    reg = Registry(registry_data())
    scenarios = []

    def scenario(name, contracts, events, steps):
        led = StatusLedger(reg)
        for key, ev, c, at, kw in events:
            led.record(key, ev, c["id"], canonical.digest(c), at, **kw)
        envs = [C.sign(c, KA if c["issuer"] == KIDA else KB) for c in contracts]
        now = [C.parse_time("2026-10-26T10:00:00Z")]
        mon = Monitor(reg, led, clock=lambda: now[0])
        for e in envs:
            assert not mon.add_contract(e, C.parse_time("2026-10-26T00:00:00Z")), name
        out = []
        for s in steps:
            if "reset" in s:
                mon.reset(s["reset"])
                out.append({"reset": s["reset"]})
                continue
            at = C.parse_time(s["at"])
            args = {k: v for k, v in s.items() if k not in ("at", "subject", "verb", "resource")}
            d = mon.check(s["subject"], s["verb"], s["resource"], at=at, **args)
            out.append({**s, "expect": d.to_dict()})
        scenarios.append({"name": name, "contracts": envs, "ledger": led.entries, "steps": out})

    c1 = base_contract()
    iss = lambda c, t="2026-10-26T09:00:00Z", **kw: (KA, "issue", c, t, kw)
    A = "agent-1"
    t = lambda m, s=0: f"2026-10-26T10:{m:02d}:{s:02d}Z"
    scenario("grants, limits, influence, defaults", [c1], [iss(c1)], [
        {"at": t(0), "subject": A, "verb": "query", "resource": "crm/accounts/42", "tokens": 500},
        {"at": t(1), "subject": A, "verb": "invoke", "resource": "tools/shell", "tool_calls": 1},
        {"at": t(2), "subject": A, "verb": "invoke", "resource": "tools/search", "tool_calls": 4},
        {"at": t(3), "subject": A, "verb": "invoke", "resource": "tools/search", "tokens": 5000, "depth": 3},
        {"at": t(4), "subject": A, "verb": "query", "resource": "hr/salaries"},
        {"at": t(5), "subject": A, "verb": "invoke", "resource": "tools/search", "influence": "persuasive"},
        {"at": t(6), "subject": "agent-2", "verb": "query", "resource": "crm/x"},
        {"at": t(7), "subject": A, "verb": "teleport", "resource": "crm/x"},
        {"at": t(8), "subject": A, "verb": "query", "resource": "crm/*"},
        {"at": t(9), "subject": A, "verb": "query", "resource": "crm/x", "tokens": -1},
        {"at": t(10), "subject": A, "verb": "query", "resource": "crm/../hr"},
        {"at": t(11), "subject": A, "verb": "query", "resource": "crm/a%2Fb"},
        {"at": t(12), "subject": A, "verb": "x-acme-DELETE", "resource": "crm/a"},
        {"at": t(13), "subject": A, "verb": "query", "resource": "crm/a", "session": "bad\tsession"},
    ])
    scenario("composite sequences per session", [c1], [iss(c1)], [
        {"at": t(0), "subject": A, "verb": "query", "resource": "secrets/db", "session": "s1"},
        {"at": t(1), "subject": A, "verb": "query", "resource": "crm/a", "session": "s1"},
        {"at": t(2), "subject": A, "verb": "invoke", "resource": "net/upload", "session": "s1"},
        {"at": t(3), "subject": A, "verb": "invoke", "resource": "net/upload", "session": "s2"},
        {"at": t(4), "subject": A, "verb": "invoke", "resource": "net/upload"},
        {"at": t(5), "subject": A, "verb": "query", "resource": "secrets/key", "session": "s3"},
        *[{"at": t(6, i), "subject": A, "verb": "query", "resource": "crm/a", "session": "s3"} for i in range(30)],
        {"at": t(7), "subject": A, "verb": "invoke", "resource": "net/upload", "session": "s3"},
    ])
    scenario("pressure: escalation, release, lock, reset", [c1], [iss(c1)], [
        *[{"at": t(0, i), "subject": A, "verb": "invoke", "resource": "tools/search", "tokens": 1000, "tool_calls": 1, "depth": 1}
          for i in range(8)],
        {"at": t(1), "subject": A, "verb": "query", "resource": "crm/a"},
        {"reset": A},
        {"at": t(2), "subject": A, "verb": "query", "resource": "crm/a"},
    ])
    c_strict = base_contract(id="ctr-strict", limits={"max_tokens": 100, "max_tool_calls": 1, "max_depth": 0,
                                                      "max_influence": "inert",
                                                      "pressure": {"escalation_threshold": "0.3", "release_threshold": "0.5"}},
                             grants=[{"verb": "query", "resource": "crm/**", "effect": "allow"},
                                     {"verb": "invoke", "resource": "net/**", "effect": "deny"}], composite=[])
    scenario("two contracts: deny overrides, most restrictive limits", [c1, c_strict], [iss(c1), iss(c_strict)], [
        {"at": t(0), "subject": A, "verb": "invoke", "resource": "net/search"},
        {"at": t(1), "subject": A, "verb": "query", "resource": "crm/a", "tokens": 500},
        {"at": t(2), "subject": A, "verb": "query", "resource": "crm/a", "tokens": 50, "influence": "informational"},
        {"at": t(3), "subject": A, "verb": "query", "resource": "crm/a", "tokens": 50, "influence": "inert"},
        {"at": t(4), "subject": A, "verb": "invoke", "resource": "tools/search", "tool_calls": 3},
        {"at": t(5), "subject": A, "verb": "invoke", "resource": "tools/search", "tool_calls": 3},
        {"at": t(6), "subject": A, "verb": "invoke", "resource": "tools/search", "tool_calls": 3},
    ])
    scenario("ledger: not issued, suspend, partial revoke, revoke, supersede",
             [c1, base_contract(id="ctr-2", supersedes="ctr-1", grants=[{"verb": "query", "resource": "hr/**", "effect": "allow"}], composite=[])],
             [iss(c1), (KA, "suspend", c1, "2026-10-26T10:01:00Z", {}), (KA, "resume", c1, "2026-10-26T10:02:00Z", {}),
              (KA, "revoke_grants", c1, "2026-10-26T10:03:00Z", {"grants": [0]}),
              (KA, "issue", base_contract(id="ctr-2", supersedes="ctr-1", grants=[{"verb": "query", "resource": "hr/**", "effect": "allow"}], composite=[]),
               "2026-10-26T10:04:00Z", {"supersedes": "ctr-1"})],
             [{"at": "2026-10-26T08:00:00Z", "subject": A, "verb": "query", "resource": "crm/a"},
              {"at": t(0, 30), "subject": A, "verb": "query", "resource": "crm/a"},
              {"at": t(1, 30), "subject": A, "verb": "query", "resource": "crm/a"},
              {"at": t(2, 30), "subject": A, "verb": "query", "resource": "crm/a"},
              {"at": t(3, 30), "subject": A, "verb": "query", "resource": "crm/a"},
              {"at": t(3, 30), "subject": A, "verb": "invoke", "resource": "tools/search"},
              {"at": t(4, 30), "subject": A, "verb": "invoke", "resource": "tools/search"},
              {"at": t(4, 30), "subject": A, "verb": "query", "resource": "hr/a"}])
    cb = base_contract(id="ctr-b", issuer=KIDB)
    scenario("issuer key revoked, contract window", [cb, base_contract(id="ctr-late", not_before="2026-12-01T00:00:00Z")],
             [(KB, "issue", cb, "2026-10-26T09:00:00Z", {}),
              iss(base_contract(id="ctr-late", not_before="2026-12-01T00:00:00Z"))],
             [{"at": t(0), "subject": A, "verb": "query", "resource": "crm/a"},
              {"at": "2026-11-01T00:00:00Z", "subject": A, "verb": "query", "resource": "crm/a"},
              {"at": "2026-12-01T00:00:00Z", "subject": A, "verb": "query", "resource": "crm/a"},
              {"at": "2027-01-01T00:00:00Z", "subject": A, "verb": "query", "resource": "crm/a"}])
    return {"description": ("for each scenario: build a registry from 'registry', a ledger by appending 'ledger', a "
                            "monitor with each signed contract added at 2026-10-26T00:00:00Z, then run the steps in order "
                            "(check with the given fields, or reset); each decision must equal 'expect'"),
            "registry": registry_data(), "scenarios": scenarios}


def main() -> int:
    write("canonical.json", canonical_vectors())
    write("keys.json", key_vectors())
    write("contracts.json", contract_vectors())
    write("ledger.json", ledger_vectors())
    write("decisions.json", decision_vectors())
    if CHECK:
        if DIFF:
            print("vectors are out of date: " + ", ".join(DIFF))
            return 1
        print("vectors are up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
