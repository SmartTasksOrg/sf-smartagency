"""Trusted issuer keys (spec/SPEC.md section 5).

A registry file is

    {"schema": "smartagency.registry/1",
     "keys": [{"kid": "ed25519:...", "public_key": "<base64url, 32 bytes>", "name": "...",
               "not_before": "2026-10-26T00:00:00Z", "not_after": "2027-10-26T00:00:00Z",
               "revoked_at": "2026-12-01T00:00:00Z"}]}

``not_after`` and ``revoked_at`` are optional. A key is trusted at time t when not_before <= t, t < not_after,
and t < revoked_at. A revoked key stops vouching for everything it signed, from revoked_at on.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from . import keys
from .contract import parse_time

SCHEMA_ID = "smartagency.registry/1"


class RegistryError(ValueError):
    pass


class Registry:
    def __init__(self, data: Any | None = None):
        self._keys: dict[str, dict] = {}
        if data is not None:
            self._load(data)

    @classmethod
    def from_file(cls, path: str) -> "Registry":
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (UnicodeDecodeError, ValueError, RecursionError) as e:
            raise RegistryError(f"{path}: not JSON ({type(e).__name__})") from None
        return cls(data)

    def _load(self, data: Any) -> None:
        if not isinstance(data, dict) or data.get("schema") != SCHEMA_ID or not isinstance(data.get("keys"), list):
            raise RegistryError(f"a registry is an object with schema {SCHEMA_ID!r} and a 'keys' list")
        for i, k in enumerate(data["keys"]):
            self.add(k, where=f"keys/{i}")

    def add(self, entry: Any, where: str = "key") -> None:
        if not isinstance(entry, dict):
            raise RegistryError(f"{where}: not an object")
        allowed = {"kid", "public_key", "name", "not_before", "not_after", "revoked_at"}
        extra = set(entry) - allowed
        if extra:
            raise RegistryError(f"{where}: unknown fields {sorted(extra)}")
        for f in ("kid", "public_key", "name", "not_before"):
            if not isinstance(entry.get(f), str):
                raise RegistryError(f"{where}: {f} is required and must be a string")
        try:
            pub = keys.public_from_b64(entry["public_key"])
        except ValueError as e:
            raise RegistryError(f"{where}: public_key: {e}") from None
        if keys.key_id(pub) != entry["kid"]:
            raise RegistryError(f"{where}: kid does not match the public key")
        times = {}
        for f in ("not_before", "not_after", "revoked_at"):
            if f in entry:
                try:
                    times[f] = parse_time(entry[f])
                except (TypeError, ValueError):
                    raise RegistryError(f"{where}: {f} must be YYYY-MM-DDTHH:MM:SSZ") from None
        if "not_after" in times and times["not_after"] <= times["not_before"]:
            raise RegistryError(f"{where}: not_after must be later than not_before")
        if entry["kid"] in self._keys:
            raise RegistryError(f"{where}: duplicate kid {entry['kid']}")
        self._keys[entry["kid"]] = {"public": pub, **times, "name": entry["name"]}

    def public_key(self, kid: str, at: datetime):
        k = self._keys.get(kid)
        if k is None or at < k["not_before"]:
            return None
        if "not_after" in k and at >= k["not_after"]:
            return None
        if "revoked_at" in k and at >= k["revoked_at"]:
            return None
        return k["public"]

    def kids(self) -> list[str]:
        return sorted(self._keys)


def entry_for(private, name: str, not_before: str, not_after: str | None = None) -> dict:
    """A registry entry for a key (the public half only)."""
    pub = private.public_key()
    e = {"kid": keys.key_id(pub), "public_key": keys.b64e(keys.public_raw(pub)), "name": name, "not_before": not_before}
    if not_after:
        e["not_after"] = not_after
    return e
