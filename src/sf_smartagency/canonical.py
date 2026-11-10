"""Canonical JSON: the bytes that are hashed and signed.

The same rules as SmartFabric's wire format (sf_smartfabric.wire.canonical_json): UTF-8, keys sorted,
no insignificant whitespace. Contracts and ledger entries hold no floats (numbers that need a fraction
are decimal strings), so the bytes are the same in every language.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_DEPTH = 32


def _check(obj: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("nested deeper than 32 levels")
    if obj is None or isinstance(obj, bool) or isinstance(obj, str):
        if isinstance(obj, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in obj):
            raise ValueError("string holds an unpaired surrogate")
        return
    if isinstance(obj, int):
        if not -(2 ** 53) < obj < 2 ** 53:
            raise ValueError("integer outside the interoperable range (|n| < 2**53)")
        return
    if isinstance(obj, float):
        raise ValueError("floats are not allowed in signed objects; use a decimal string")
    if isinstance(obj, list):
        for v in obj:
            _check(v, depth + 1)
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError("object keys must be strings")
            _check(k, depth + 1)
            _check(v, depth + 1)
        return
    raise ValueError(f"{type(obj).__name__} is not JSON data")


def encode(obj: Any) -> bytes:
    """Canonical bytes of plain JSON data (dict, list, str, int, bool, None; no floats)."""
    _check(obj)
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(obj: Any) -> str:
    """``sha256:`` plus the hex SHA-256 of the canonical bytes."""
    return "sha256:" + hashlib.sha256(encode(obj)).hexdigest()
