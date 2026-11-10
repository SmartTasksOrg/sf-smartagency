"""Ed25519 keys, key ids and detached signatures (RFC 8032, through the `cryptography` package).

A key id is ``ed25519:`` plus the first 32 hex digits of SHA-256(raw 32-byte public key). Signatures are
URL-safe base64 without padding. Only Ed25519 is accepted: there is no fallback algorithm, so a contract
cannot be downgraded to a weaker scheme (SPEC.md, "Signatures").
"""
from __future__ import annotations

import base64
import hashlib
import os
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ALG = "ed25519"


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64d(s: str) -> bytes:
    if not isinstance(s, str) or not s or len(s) > 4096:
        raise ValueError("not a base64url string")
    if any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in s):
        raise ValueError("not a base64url string")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64e(raw) != s:                       # one string per value: no unused bits, no padding
        raise ValueError("not a canonical base64url string")
    return raw


def public_raw(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(public: Ed25519PublicKey | bytes) -> str:
    raw = public if isinstance(public, bytes) else public_raw(public)
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return ALG + ":" + hashlib.sha256(raw).hexdigest()[:32]


def generate() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def from_seed(seed: bytes) -> Ed25519PrivateKey:
    """A key from a 32-byte seed. For tests, vectors and the demo only: a real key comes from generate()."""
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_from_b64(s: str) -> Ed25519PublicKey:
    raw = b64d(s)
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def sign(private: Ed25519PrivateKey, message: bytes) -> str:
    return b64e(private.sign(message))


def verify(public: Ed25519PublicKey, message: bytes, signature: str) -> bool:
    try:
        sig = b64d(signature)
    except ValueError:
        return False
    if len(sig) != 64:
        return False
    try:
        public.verify(sig, message)
        return True
    except InvalidSignature:
        return False


def save_private(private: Ed25519PrivateKey, path: str) -> None:
    """Write a PKCS#8 PEM private key that only the owner can read. Refuses to overwrite."""
    data = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def load_private(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key
