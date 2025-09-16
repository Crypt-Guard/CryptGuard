# -*- coding: utf-8 -*-
"""
metadata.py - JSON de metadados protegido por ChaCha20-Poly1305

Formato no disco:
- salt (META_SALT_SIZE)
- nonce (12 bytes)
- chacha20-poly1305(ciphertext + tag)

O JSON pode conter campo opcional "exp" (timestamp UNIX, UTC). Use
is_expired(meta) para validação de expiração em camadas superiores.
"""

from __future__ import annotations

import json
import secrets
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .config import META_SALT_SIZE
from .kdf import derive_key_sb as _derive_meta_key_sb  # Argon2id → chave
from .secure_bytes import SecureBytes
from .utils import write_atomic_secure
from .fileformat_v5 import canonical_json_bytes

# Domain separation para o envelope de metadados
AAD_META: bytes = b"CG2/v5 meta|v1"
META_NONCE_SIZE = 12


# JSON helpers
def _pack(obj: dict[str, Any]) -> bytes:
    """dict → bytes (JSON canônico/minificado, UTF-8, sem NaN/Inf)"""
    return canonical_json_bytes(obj)


def _unpack(b: bytes) -> dict[str, Any]:
    """bytes → dict"""
    return json.loads(b.decode("utf-8"))


# API pública
def encrypt_meta_json(
    meta_path: Path,
    meta: dict[str, Any],
    pwd_sb: SecureBytes,
    expires_at: int | None = None,
) -> None:
    """
    Cria/atualiza meta_path com JSON criptografado.
    Se expires_at for fornecido, grava como campo "exp" (UTC, segundos).
    """
    if expires_at is not None:
        # Garantir cópia para não alterar o dicionário original
        meta = dict(meta)
        meta["exp"] = int(expires_at)

    salt = secrets.token_bytes(META_SALT_SIZE)
    params = {"salt": salt}
    key = _derive_meta_key_sb(pwd_sb, params)  # → SecureBytes
    nonce = secrets.token_bytes(META_NONCE_SIZE)

    cipher = ChaCha20Poly1305(bytes(key.view()))
    blob = salt + nonce + cipher.encrypt(nonce, _pack(meta), AAD_META)

    write_atomic_secure(meta_path, blob)
    key.clear()


def decrypt_meta_json(meta_path: Path, pwd_sb: SecureBytes) -> dict[str, Any]:
    """
    Lê, decifra e devolve o JSON.

    Não dispara erro se expirado — deixa a decisão para quem chamou,
    mas disponibiliza o helper is_expired(meta).
    """
    blob = Path(meta_path).read_bytes()
    if len(blob) < (META_SALT_SIZE + META_NONCE_SIZE + 16):  # 16 = tag do AEAD
        raise ValueError("Metadata blob too short")
    salt = blob[:META_SALT_SIZE]
    nonce = blob[META_SALT_SIZE : META_SALT_SIZE + META_NONCE_SIZE]
    ct = blob[META_SALT_SIZE + META_NONCE_SIZE :]

    params = {"salt": salt}
    key = _derive_meta_key_sb(pwd_sb, params)
    cipher = ChaCha20Poly1305(bytes(key.view()))
    try:
        data = cipher.decrypt(nonce, ct, AAD_META)
    except Exception:
        # Backward-compat: allow legacy blobs without AAD
        data = cipher.decrypt(nonce, ct, None)
    key.clear()
    return _unpack(data)


# Auxiliares extra
def build_meta(base: dict[str, Any], expires_at: int | None = None) -> dict[str, Any]:
    """Conveniência: devolve base + exp (se definido)."""
    if expires_at is not None:
        base = dict(base)
        base["exp"] = int(expires_at)
    return base


def is_expired(meta: dict[str, Any], skew_seconds: int = 0) -> bool:
    """
    True se meta contém exp e ele já ficou para trás.

    skew_seconds permite tolerância de relógio (default 0).
    """
    exp = meta.get("exp")
    return exp is not None and time.time() > exp + skew_seconds
