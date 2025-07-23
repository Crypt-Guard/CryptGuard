"""
metadata.py  –  JSON de metadados duplamente protegido

Formato do blob gravado no disco
────────────────────────────────
• Salt   (META_SALT_SIZE bytes)  – Argon2id (leve) para derivar a chave
• Nonce  (12 bytes)              – ChaCha20‑Poly1305
• Cipher (variável)              – JSON minificado  + tag autêntica

A partir desta versão o JSON aceita:

    {
        "alg": "AESCTR",
        "profile": "FAST",
        "size": 1234567,
        "ts":   1721712000,   # criação
        "exp":  1735603200    # expiração (opcional)
        ...
    }

Se **exp** estiver presente e for menor que *time.time()*,
o arquivo deve ser considerado expirado.
"""
from __future__ import annotations

import secrets, json, time
from pathlib import Path
from typing import Dict, Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .secure_bytes import SecureBytes
from .kdf          import derive_meta_key          # Argon2id → chave
from .utils        import write_atomic_secure
from .config       import META_SALT_SIZE


# ─────────────────────────── JSON helpers ──────────────────────────────
def _pack(obj: Dict[str, Any]) -> bytes:
    """dict → bytes (JSON minificado)"""
    return json.dumps(obj, separators=(",", ":")).encode()


def _unpack(b: bytes) -> Dict[str, Any]:
    """bytes → dict"""
    return json.loads(b.decode())


# ─────────────────────────── API pública ───────────────────────────────
def encrypt_meta_json(
    meta_path: Path,
    meta: Dict[str, Any],
    pwd_sb: SecureBytes,
    expires_at: Optional[int] = None,
) -> None:
    """
    Cria/atualiza *meta_path* com JSON criptografado.
    Se ``expires_at`` for fornecido, grava como campo ``"exp"`` (UTC, segundos).
    """
    if expires_at is not None:
        # Garantir cópia para não alterar o dicionário original passado pelo chamador
        meta = dict(meta)
        meta["exp"] = int(expires_at)

    salt  = secrets.token_bytes(META_SALT_SIZE)
    key   = derive_meta_key(pwd_sb, salt)           # → SecureBytes
    nonce = secrets.token_bytes(12)

    cipher = ChaCha20Poly1305(key.to_bytes())
    blob   = salt + nonce + cipher.encrypt(nonce, _pack(meta), None)

    write_atomic_secure(meta_path, blob)
    key.clear()


def decrypt_meta_json(meta_path: Path, pwd_sb: SecureBytes) -> Dict[str, Any]:
    """
    Lê, decifra e devolve o JSON.

    *Não* dispara erro se expirado – deixa a decisão para quem chamou,
    mas disponibiliza o helper ``is_expired(meta)`` abaixo.
    """
    blob = Path(meta_path).read_bytes()
    salt   = blob[:META_SALT_SIZE]
    nonce  = blob[META_SALT_SIZE : META_SALT_SIZE + 12]
    ct     = blob[META_SALT_SIZE + 12 :]

    key  = derive_meta_key(pwd_sb, salt)
    data = ChaCha20Poly1305(key.to_bytes()).decrypt(nonce, ct, None)
    key.clear()
    return _unpack(data)


# ─────────────────────────── Auxiliares extra ──────────────────────────
def build_meta(base: Dict[str, Any], expires_at: Optional[int] = None) -> Dict[str, Any]:
    """
    Conveniência: devolve *base* + ``exp`` (se definido).
    """
    if expires_at is not None:
        base = dict(base)
        base["exp"] = int(expires_at)
    return base


def is_expired(meta: Dict[str, Any], skew_seconds: int = 0) -> bool:
    """
    ``True`` se *meta* contém ``exp`` e ele já ficou para trás.

    ``skew_seconds`` permite tolerância de relógio (default 0).
    """
    exp = meta.get("exp")
    return exp is not None and time.time() > exp + skew_seconds
