"""Run the conformance vectors (spec/conformance/*.json) against this implementation.

``run_dir(path)`` returns (number of checks, list of failure messages). A port implements the same five
files; spec/SPEC.md section 10 says what each check compares.
"""
from __future__ import annotations

import json
import os

from . import canonical, contract as C, keys
from ._bundled import path as data_path
from .ledger import LedgerError, StatusLedger
from .monitor import Monitor
from .registry import Registry

FILES = ("canonical.json", "keys.json", "contracts.json", "ledger.json", "decisions.json")


def _load(d, name):
    with open(os.path.join(d, name), encoding="utf-8") as f:
        return json.load(f)


def run_dir(d: str) -> tuple[int, list[str]]:
    total, fails = 0, []

    def check(ok: bool, msg: str):
        nonlocal total
        total += 1
        if not ok:
            fails.append(msg)

    v = _load(d, "canonical.json")
    for i, c in enumerate(v["cases"]):
        check(canonical.encode(c["input"]).decode("utf-8") == c["canonical"], f"canonical {i}: bytes")
        check(canonical.digest(c["input"]) == c["digest"], f"canonical {i}: digest")
    for c in v["refused"]:
        try:
            canonical.encode(c["input"])
            check(False, f"canonical refused {c['name']}: accepted")
        except ValueError:
            check(True, "")

    v = _load(d, "keys.json")
    for i, c in enumerate(v["keys"]):
        k = keys.from_seed(bytes.fromhex(c["seed_hex"]))
        pub = k.public_key()
        check(keys.b64e(keys.public_raw(pub)) == c["public_key"], f"keys {i}: public key")
        check(keys.key_id(pub) == c["kid"], f"keys {i}: kid")
        check(keys.sign(k, bytes.fromhex(c["message_hex"])) == c["signature"], f"keys {i}: signature")
    for c in v["verify"]:
        got = keys.verify(keys.public_from_b64(c["public_key"]), bytes.fromhex(c["message_hex"]), c["signature"])
        check(got == c["valid"], f"keys verify {c['name']}: {got}")

    v = _load(d, "contracts.json")
    reg = Registry(v["registry"])
    at = C.parse_time(v["verify_at"])
    for c in v["contracts"]:
        got = not C.validate(c["contract"])
        check(got == c["valid"], f"contract {c['name']}: valid={got}")
    for c in v["envelopes"]:
        got = not C.envelope_problems(c["envelope"], lambda kid: reg.public_key(kid, at))
        check(got == c["valid"], f"envelope {c['name']}: valid={got}")
    for c in v["resource_matches"]:
        got = C.resource_matches(c["pattern"], c["resource"])
        check(got == c["matches"], f"match {c['pattern']} {c['resource']}: {got}")

    v = _load(d, "ledger.json")
    reg = Registry(v["registry"])
    led = StatusLedger(reg)
    try:
        for e in v["valid"]["entries"]:
            led.append(e)
        check(True, "")
    except LedgerError as e:
        check(False, f"ledger valid: refused ({e})")
    for s in v["valid"]["statuses"]:
        got = led.status(s["id"], C.parse_time(s["at"]))
        check(got == s["status"], f"ledger status {s['id']} at {s['at']}: {got}")
    for case in v["invalid"]:
        bad = StatusLedger(reg)
        try:
            for e in case["entries"]:
                bad.append(e)
            check(False, f"ledger invalid {case['name']}: accepted")
        except LedgerError:
            check(True, "")

    v = _load(d, "decisions.json")
    reg = Registry(v["registry"])
    for sc in v["scenarios"]:
        led = StatusLedger(reg)
        for e in sc["ledger"]:
            led.append(e)
        mon = Monitor(reg, led)
        for env in sc["contracts"]:
            mon.add_contract(env, C.parse_time("2026-10-26T00:00:00Z"))
        for i, s in enumerate(sc["steps"]):
            if "reset" in s:
                mon.reset(s["reset"])
                continue
            args = {k: s[k] for k in ("tokens", "tool_calls", "depth", "influence", "session") if k in s}
            d_ = mon.check(s["subject"], s["verb"], s["resource"], at=C.parse_time(s["at"]), **args)
            check(d_.to_dict() == s["expect"], f"decision {sc['name']} step {i}: {d_.to_dict()} != {s['expect']}")
    return total, fails


def run_bundled() -> tuple[int, list[str]]:
    return run_dir(data_path("conformance"))
