"""
hkdf_utils.py — HKDF helpers for deriving sub-keys from a 32-byte master key.

- RFC5869 HKDF-SHA256 (pure, via hashlib/hmac), 32-byte subkeys.
- derive_keys(master, info, salt) keeps current API for (enc_key, hmac_key).
- derive_subkey(master_key32, label, length=32, context={}) for domain-separated subkeys.
"""

from __future__ import annotations

import hashlib
import hmac

from .fileformat_v5 import canonical_json_bytes
from .secure_bytes import SecureBytes


def _as_bytes(data: SecureBytes | bytes | bytearray | memoryview) -> bytes:
    if isinstance(data, SecureBytes):
        return bytes(data.view())
    if isinstance(data, memoryview):
        return data.tobytes() if not data.c_contiguous else bytes(data)
    return bytes(data)


_HASH = hashlib.sha256


def _hkdf_extract(salt: bytes | None, ikm: bytes) -> bytes:
    if salt is None:
        salt = b"\x00" * _HASH().digest_size
    return hmac.new(salt, ikm, _HASH).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length <= 0 or length > 255 * _HASH().digest_size:
        raise ValueError("HKDF length inválido")
    okm = b""
    t = b""
    n = 0
    while len(okm) < length:
        n += 1
        t = hmac.new(prk, t + info + bytes([n]), _HASH).digest()
        okm += t
    return okm[:length]


def derive_keys(
    master: SecureBytes | bytes | bytearray | memoryview,
    *,
    info: bytes,
    salt: bytes | None,
) -> tuple[bytes, bytes]:
    """Backward-compatible API: returns (enc_key32, hmac_key32)."""
    ikm = _as_bytes(master)
    prk = _hkdf_extract(salt, ikm)
    okm = _hkdf_expand(prk, info, 64)
    return okm[:32], okm[32:]


def derive_subkey(
    master_key32: bytes,
    label: str,
    length: int = 32,
    context: dict | None = None,
    salt: bytes | None = None,
) -> bytes:
    """
    RFC5869 HKDF-SHA256 with domain separation:
      info = b"CG2/v5 hkdf|" + label.encode('utf-8') + b"|" + canonical_json(context)
    Typical:
      stream_key = derive_subkey(key32, "stream")
    """
    if not isinstance(master_key32, bytes | bytearray) or len(master_key32) != 32:
        raise ValueError("master_key32 deve ter 32 bytes")
    info = b"CG2/v5 hkdf|" + label.encode("utf-8") + b"|" + canonical_json_bytes(context or {})
    prk = _hkdf_extract(salt, bytes(master_key32))
    return _hkdf_expand(prk, info, int(length))


__all__ = ["derive_keys", "derive_subkey"]
