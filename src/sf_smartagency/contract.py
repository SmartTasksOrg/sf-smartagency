"""Contracts: what one agent may do, signed by an issuer (spec/SPEC.md sections 2 to 4).

A contract is plain JSON data checked against ``spec/schema/contract.schema.json`` plus the semantic rules
below. A signed contract is an *envelope*:

    {"contract": {...}, "signature": {"alg": "ed25519", "kid": "<issuer key id>", "sig": "<base64url>"}}

where ``sig`` is the Ed25519 signature over the canonical bytes of ``contract`` and ``kid`` equals
``contract["issuer"]``.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

import jsonschema
from sf_smartfabric import PressureConfig, is_known_verb

from . import canonical, keys
from ._bundled import path as data_path

SCHEMA_ID = "smartagency.contract/1"
INFLUENCE = ("inert", "informational", "persuasive", "adaptive", "autonomous")
PRESSURE_FIELDS = ("escalation_threshold", "release_threshold", "dissipation_per_step",
                   "token_coefficient", "tool_coefficient", "depth_coefficient")
_TIME = "%Y-%m-%dT%H:%M:%SZ"
_SCHEMA: dict | None = None


def schema() -> dict:
    global _SCHEMA
    if _SCHEMA is None:
        with open(data_path("schema", "contract.schema.json"), encoding="utf-8") as f:
            _SCHEMA = json.load(f)
    return _SCHEMA


_TIME_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def parse_time(s: str) -> datetime:
    """Exactly YYYY-MM-DDTHH:MM:SSZ (zero-padded, UTC); anything else raises ValueError."""
    if not isinstance(s, str) or not _TIME_RE.match(s):
        raise ValueError(f"time must be YYYY-MM-DDTHH:MM:SSZ, not {str(s)[:40]!r}")
    return datetime.strptime(s, _TIME).replace(tzinfo=timezone.utc)


def format_time(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime(_TIME)


def pressure_config(contract: dict) -> PressureConfig:
    """The SmartFabric pressure configuration a contract sets (SmartFabric defaults for absent fields)."""
    p = contract.get("limits", {}).get("pressure", {}) or {}
    fields = {k: float(Decimal(p[k])) for k in PRESSURE_FIELDS if k in p}
    esc = fields.get("escalation_threshold", PressureConfig.escalation_threshold)
    # the warning band is SmartFabric telemetry only; it follows a lowered escalation threshold
    fields["warning_band"] = min(PressureConfig.warning_band, esc)
    return PressureConfig(**fields)


def _resource_ok(r: str) -> str | None:
    segs = r.split("/")
    if any(s == "" for s in segs):
        return "has an empty path segment"
    for s in segs:
        if "*" in s and s not in ("*", "**"):
            return "uses '*' inside a segment (only whole '*' or '**' segments are wildcards)"
        if s in (".", ".."):
            return "has a '.' or '..' segment (paths are compared literally, so they must be normalised)"
    if "%" in r or "\\" in r:
        return "contains '%' or a backslash (paths are compared literally, so they must be decoded and normalised)"
    if segs.count("**") > 4:
        return "has more than four '**' segments"
    return None


def validate(contract: Any) -> list[str]:
    """All problems with ``contract``: schema errors first (sorted), then semantic errors. Empty means valid."""
    errors: list[str] = []
    try:
        canonical.encode(contract)
    except ValueError as e:
        return [f"not signable JSON data: {e}"]
    v = jsonschema.Draft7Validator(schema())
    for e in sorted(v.iter_errors(contract), key=lambda e: (list(e.absolute_path), e.message)):
        where = "/".join(str(p) for p in e.absolute_path) or "(root)"
        errors.append(f"schema: {where}: {e.message}"[:300])
    if errors:
        return errors
    for i, g in enumerate(contract["grants"]):
        if g["verb"] != "*" and not is_known_verb(g["verb"]):
            errors.append(f"grants/{i}/verb: {g['verb']!r} is not a SmartFabric CIR verb or an x- extension")
        bad = _resource_ok(g["resource"])
        if bad:
            errors.append(f"grants/{i}/resource: {bad}")
    for i, c in enumerate(contract.get("composite", [])):
        for j, p in enumerate(c["deny_sequence"]):
            if p["verb"] != "*" and not is_known_verb(p["verb"]):
                errors.append(f"composite/{i}/deny_sequence/{j}/verb: {p['verb']!r} is not a known verb")
            bad = _resource_ok(p["resource"])
            if bad:
                errors.append(f"composite/{i}/deny_sequence/{j}/resource: {bad}")
    names = [c["name"] for c in contract.get("composite", [])]
    if len(names) != len(set(names)):
        errors.append("composite: rule names must be unique")
    try:
        nb, ex = parse_time(contract["not_before"]), parse_time(contract["expires"])
        if ex <= nb:
            errors.append("expires must be later than not_before")
    except ValueError as e:
        errors.append(f"time: {e}")
    try:
        pressure_config(contract).validate()
    except (ValueError, InvalidOperation) as e:
        errors.append(f"limits/pressure: {e}")
    if contract.get("supersedes") == contract["id"]:
        errors.append("supersedes: a contract cannot supersede itself")
    return errors


def sign(contract: dict, private) -> dict:
    """Sign a valid contract with the issuer's private key. The key must match ``contract['issuer']``."""
    problems = validate(contract)
    if problems:
        raise ValueError("invalid contract: " + "; ".join(problems[:5]))
    kid = keys.key_id(private.public_key())
    if kid != contract["issuer"]:
        raise ValueError(f"the signing key is {kid}, but the contract names issuer {contract['issuer']}")
    return {"contract": contract, "signature": {"alg": keys.ALG, "kid": kid, "sig": keys.sign(private, canonical.encode(contract))}}


def envelope_problems(envelope: Any, public_key_for) -> list[str]:
    """Problems with a signed envelope. ``public_key_for(kid)`` returns the issuer's public key or None
    (the caller checks the key's validity period and revocation). Empty means the envelope is valid."""
    if not isinstance(envelope, dict) or set(envelope) != {"contract", "signature"}:
        return ["an envelope is an object with exactly 'contract' and 'signature'"]
    sig = envelope["signature"]
    if not isinstance(sig, dict) or set(sig) != {"alg", "kid", "sig"}:
        return ["signature must be an object with exactly 'alg', 'kid' and 'sig'"]
    if sig["alg"] != keys.ALG:
        return [f"signature alg {sig['alg']!r} is not accepted (only ed25519)"]
    problems = validate(envelope["contract"])
    if problems:
        return problems
    c = envelope["contract"]
    if sig["kid"] != c["issuer"]:
        return ["signature kid does not match the contract's issuer"]
    pub = public_key_for(sig["kid"])
    if pub is None:
        return [f"issuer key {sig['kid']} is not trusted"]
    if not keys.verify(pub, canonical.encode(c), sig["sig"]):
        return ["signature does not verify"]
    return []


# ---------------------------------------------------------------- matching (SPEC.md section 4)

def resource_matches(pattern: str, resource: str) -> bool:
    """'*' matches exactly one path segment, '**' zero or more; everything else is literal.
    Dynamic programming over segments: time proportional to len(pattern) * len(resource)."""
    p, r = pattern.split("/"), resource.split("/")
    # ok[j] is True when p[:i] matches r[:j]
    ok = [True] + [False] * len(r)
    for seg in p:
        if seg == "**":
            run = False
            nxt = []
            for j in range(len(r) + 1):
                run = run or ok[j]
                nxt.append(run)
        else:
            nxt = [False] + [ok[j] and (seg == "*" or seg == r[j]) for j in range(len(r))]
        ok = nxt
    return ok[len(r)]


def verb_matches(pattern: str, verb: str) -> bool:
    return pattern == "*" or pattern == verb


def action_matches(pattern: dict, verb: str, resource: str) -> bool:
    return verb_matches(pattern["verb"], verb) and resource_matches(pattern["resource"], resource)


_ACTION_RE = re.compile(r"^[A-Za-z0-9._~:@+=/-]{1,256}$")
_VERB_RE = re.compile(r"^([a-z]+(\.[a-z]+)?|x-[a-z0-9]+-[a-z0-9]+(\.[a-z0-9]+)*)$")


def action_problem(verb: Any, resource: Any) -> str | None:
    """Why an action's verb or resource is malformed, or None. Exact ``str`` only (no subclasses)."""
    if type(verb) is not str or len(verb) > 64 or not _VERB_RE.match(verb) or not is_known_verb(verb):
        return "verb must be a SmartFabric CIR verb or an x- extension"
    if type(resource) is not str or not _ACTION_RE.match(resource) or "*" in resource:
        return "resource must be 1 to 256 characters from A-Z a-z 0-9 . _ ~ : @ + = / -"
    return _resource_ok(resource)
