"""sf-smartagency: contracts for AI agents, from the command line.

    sf-smartagency demo
    sf-smartagency keygen --out issuer.pem --name "SmartTasks issuer"     # prints the registry entry
    sf-smartagency validate contract.json
    sf-smartagency sign contract.json --key issuer.pem --out contract.signed.json
    sf-smartagency verify contract.signed.json --registry registry.json
    sf-smartagency ledger issue  --ledger status.jsonl --registry registry.json --key issuer.pem --contract contract.signed.json
    sf-smartagency ledger suspend|resume|revoke  ... [--reason TEXT]
    sf-smartagency ledger revoke-grants ... --grants 0,3
    sf-smartagency ledger verify --ledger status.jsonl --registry registry.json
    sf-smartagency status --ledger status.jsonl --registry registry.json --id ctr-1 [--at 2026-10-26T09:00:00Z]
    sf-smartagency check --registry registry.json --ledger status.jsonl --contracts a.json [b.json ...] \\
        --subject AGENT --verb invoke --resource tools/search [--tokens N --tool-calls N --depth N
        --influence informational --at TIME --audit audit.jsonl --audit-key monitor.pem --anchor HEAD]
    sf-smartagency vectors

`check` decides one action on its own: it has no pressure history and no session, so composite rules
across actions and pressure need a long-lived Monitor in your process (README, "In Python").

Exit codes: 0 success or allow, 1 deny or a problem found, 2 a file cannot be read or used, 3 escalate.
Output that repeats file content is JSON-escaped, so control characters in a contract cannot reach the terminal.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from . import __version__, canonical, contract as C, keys
from .audit import AuditLog
from .ledger import LedgerError, StatusLedger
from .monitor import Monitor
from .registry import Registry, RegistryError, entry_for

MAX_FILE = 16 * 1024 * 1024


class UsageError(Exception):
    pass


def _read_json(path: str):
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_FILE + 1)
    except OSError as e:
        raise UsageError(f"cannot read {path}: {e.strerror}") from None
    if len(data) > MAX_FILE:
        raise UsageError(f"{path} is larger than 16 MiB")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise UsageError(f"{path} is not UTF-8 JSON: {type(e).__name__}") from None


def _registry(path: str) -> Registry:
    try:
        return Registry(_read_json(path))
    except RegistryError as e:
        raise UsageError(f"{path}: {e}") from None


def _ledger(path: str, reg: Registry, *, must_exist: bool = True, anchor: str | None = None) -> StatusLedger:
    try:
        return StatusLedger(reg, path, must_exist=must_exist, anchor=anchor)
    except (LedgerError, OSError) as e:
        raise UsageError(f"ledger: {e}") from None


def _key(path: str):
    try:
        return keys.load_private(path)
    except (OSError, ValueError, TypeError) as e:
        raise UsageError(f"cannot load the private key {path}: {e}") from None


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _at(s: str | None) -> datetime:
    if s is None:
        return _now()
    try:
        return C.parse_time(s)
    except ValueError:
        raise UsageError("--at must be YYYY-MM-DDTHH:MM:SSZ") from None


def _print(obj) -> None:
    print(json.dumps(obj, indent=1, ensure_ascii=True))


def cmd_keygen(a) -> int:
    k = keys.generate()
    try:
        keys.save_private(k, a.out)
    except FileExistsError:
        raise UsageError(f"{a.out} exists; refusing to overwrite a key") from None
    except OSError as e:
        raise UsageError(f"cannot write {a.out}: {e.strerror}") from None
    entry = entry_for(k, a.name, C.format_time(_now()))
    print(f"private key written to {a.out} (keep it secret; it is never printed)", file=sys.stderr)
    print("add this entry to the registry's 'keys' list:", file=sys.stderr)
    _print(entry)
    return 0


def cmd_validate(a) -> int:
    problems = C.validate(_read_json(a.file))
    for p in problems:
        print(json.dumps(p, ensure_ascii=True))
    print("valid" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


def cmd_sign(a) -> int:
    c = _read_json(a.file)
    try:
        env = C.sign(c, _key(a.key))
    except ValueError as e:
        raise UsageError(str(e)) from None
    data = json.dumps(env, indent=1, ensure_ascii=False) + "\n"
    try:
        with open(a.out, "x", encoding="utf-8") as f:
            f.write(data)
    except FileExistsError:
        raise UsageError(f"{a.out} exists; refusing to overwrite") from None
    print(f"signed {json.dumps(c['id'])} with {env['signature']['kid']} -> {a.out}")
    return 0


def cmd_verify(a) -> int:
    reg = _registry(a.registry)
    at = _at(a.at)
    env = _read_json(a.file)
    problems = C.envelope_problems(env, lambda kid: reg.public_key(kid, at))
    for p in problems:
        print(json.dumps(p, ensure_ascii=True))
    print("signature valid; contract valid" if not problems else "NOT valid")
    return 1 if problems else 0


def cmd_ledger(a) -> int:
    reg = _registry(a.registry)
    led = _ledger(a.ledger, reg, must_exist=a.action not in ("issue",), anchor=a.anchor)
    if a.action == "verify":
        print(f"{len(led.entries)} entries, chain and signatures verified")
        print(f"head: {led.head()}  (keep it where the ledger's writer cannot change it; pass it as --anchor)")
        return 0
    if not a.key or not a.contract:
        raise UsageError(f"ledger {a.action} needs --key and --contract")
    env = _read_json(a.contract)
    at = _at(a.at)
    problems = C.envelope_problems(env, lambda kid: reg.public_key(kid, at))
    if problems:
        raise UsageError("the contract does not verify: " + "; ".join(problems[:3]))
    c = env["contract"]
    grants = None
    if a.action == "revoke-grants":
        try:
            grants = [int(x) for x in (a.grants or "").split(",") if x.strip()]
        except ValueError:
            raise UsageError("--grants is a comma-separated list of grant indexes") from None
    event = {"revoke-grants": "revoke_grants"}.get(a.action, a.action)
    supersedes = c.get("supersedes") if event == "issue" else None
    try:
        e = led.record(_key(a.key), event, c["id"], canonical.digest(c), at, grants=grants,
                       supersedes=supersedes, reason=a.reason)
    except LedgerError as err:
        raise UsageError(f"refused: {err}") from None
    print(f"entry {e['seq']}: {e['event']} {json.dumps(c['id'])} at {e['at']}; head: {led.head()}")
    return 0


def cmd_status(a) -> int:
    reg = _registry(a.registry)
    led = _ledger(a.ledger, reg, anchor=a.anchor)
    _print({"id": a.id, **led.status(a.id, _at(a.at))})
    return 0


def cmd_check(a) -> int:
    reg = _registry(a.registry)
    led = _ledger(a.ledger, reg, anchor=a.anchor)
    at = _at(a.at)
    audit = None
    if a.audit:
        signer = _key(a.audit_key) if a.audit_key else None
        if signer is not None and keys.key_id(signer.public_key()) in reg.kids():
            raise UsageError("--audit-key is an issuer key in the registry: use a separate monitor key")
        try:
            audit = AuditLog(a.audit, signer=signer)
        except (OSError, ValueError) as e:
            raise UsageError(f"audit log {a.audit}: {e}") from None
    mon = Monitor(reg, led, audit, clock=lambda: at)
    for path in a.contracts:
        problems = mon.add_contract(_read_json(path), at)
        if problems:
            print(json.dumps(f"{path}: not loaded: {problems[0]}", ensure_ascii=True), file=sys.stderr)
    d = mon.check(a.subject, a.verb, a.resource, tokens=a.tokens, tool_calls=a.tool_calls, depth=a.depth,
                  influence=a.influence, at=at)
    _print(d.to_dict())
    return {"allow": 0, "deny": 1, "escalate": 3}[d.outcome]


def cmd_vectors(a) -> int:
    from .conformance import run_bundled
    total, failures = run_bundled()
    for f in failures:
        print(json.dumps(f, ensure_ascii=True))
    print(f"python: {total - len(failures)}/{total} vectors passed")
    return 1 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="sf-smartagency", description="Signed contracts for AI agents, enforced.")
    ap.add_argument("--version", action="version", version=f"SmartAgency {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo", help="run the demo (in memory)")
    p = sub.add_parser("keygen", help="new issuer key")
    p.add_argument("--out", required=True)
    p.add_argument("--name", required=True)
    p = sub.add_parser("validate", help="check an unsigned contract")
    p.add_argument("file")
    p = sub.add_parser("sign", help="sign a contract")
    p.add_argument("file")
    p.add_argument("--key", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("verify", help="verify a signed contract")
    p.add_argument("file")
    p.add_argument("--registry", required=True)
    p.add_argument("--at")
    p = sub.add_parser("ledger", help="write or verify the status ledger")
    p.add_argument("action", choices=["issue", "suspend", "resume", "revoke", "revoke-grants", "verify"])
    p.add_argument("--ledger", required=True)
    p.add_argument("--registry", required=True)
    p.add_argument("--key")
    p.add_argument("--contract")
    p.add_argument("--grants")
    p.add_argument("--reason")
    p.add_argument("--at")
    p.add_argument("--anchor", help="a head from 'ledger verify' the ledger must still contain")
    p = sub.add_parser("status", help="a contract's status")
    p.add_argument("--ledger", required=True)
    p.add_argument("--registry", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--at")
    p.add_argument("--anchor", help="a head from 'ledger verify' the ledger must still contain")
    p = sub.add_parser("check", help="decide one action")
    p.add_argument("--registry", required=True)
    p.add_argument("--ledger", required=True)
    p.add_argument("--contracts", nargs="+", required=True)
    p.add_argument("--subject", required=True)
    p.add_argument("--verb", required=True)
    p.add_argument("--resource", required=True)
    p.add_argument("--tokens", type=int, default=0)
    p.add_argument("--tool-calls", type=int, default=0)
    p.add_argument("--depth", type=int, default=0)
    p.add_argument("--influence", default="informational", choices=C.INFLUENCE)
    p.add_argument("--at")
    p.add_argument("--audit")
    p.add_argument("--audit-key", help="the monitor's private key: sign each audit record")
    p.add_argument("--anchor", help="a head from 'ledger verify' the ledger must still contain")
    sub.add_parser("vectors", help="run the bundled conformance vectors")
    return ap


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    try:
        if a.cmd == "demo":
            from .demo import run
            return run()
        return {"keygen": cmd_keygen, "validate": cmd_validate, "sign": cmd_sign, "verify": cmd_verify,
                "ledger": cmd_ledger, "status": cmd_status, "check": cmd_check, "vectors": cmd_vectors}[a.cmd](a)
    except UsageError as e:
        print(f"sf-smartagency: {json.dumps(str(e), ensure_ascii=True)[1:-1]}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
