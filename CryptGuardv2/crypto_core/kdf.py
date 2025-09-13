from __future__ import annotations
from argon2 import low_level as _argon
from .secure_bytes import SecureBytes

def _coerce_salt(params) -> bytes:
    salt = params.get("salt")
    if isinstance(salt, str):
        salt = bytes.fromhex(salt)
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
        raise ValueError("salt must be >=16 bytes")
    return bytes(salt)

def derive_key_sb(password: SecureBytes | bytes | str, params, length: int = 32) -> SecureBytes:
    """Nova API: retorna SecureBytes."""
    # password → SecureBytes
    if isinstance(password, str):
        pwd_sb = SecureBytes(password.encode())
    elif isinstance(password, SecureBytes):
        pwd_sb = password
    elif isinstance(password, (bytes, bytearray)):
        pwd_sb = SecureBytes(bytes(password))
    else:
        raise TypeError(f"Password must be str, bytes or SecureBytes, not {type(password)}")
    salt = _coerce_salt(params)
    t = int(params.get("time_cost", 2))
    m = int(params.get("memory_cost", 64 * 1024))
    p = int(params.get("parallelism", 2))

    out: bytes | None = None
    def _derive(pwd_bytes: bytes):
        nonlocal out
        out = _argon.hash_secret_raw(pwd_bytes, salt, t, m, p, length, _argon.Type.ID)

    pwd_sb.with_bytes(_derive)
    return SecureBytes(out)

# Compat — legado que retorna bytes (use apenas durante a migração)
def derive_key(password, params, length: int = 32) -> bytes:
    sb = derive_key_sb(password, params, length)
    try:
        return bytes(sb.view())  # evita cópia extra grande
    finally:
        sb.clear()

# Compat com metadata.py
def derive_meta_key(password, params, length: int = 32) -> bytes:
    return derive_key(password, params, length)

# Função usada por argon_utils.generate_key_from_password()
def generate_key_from_password(pswd_sb, salt: bytes, params: dict):
    k = derive_key_sb(pswd_sb, {**params, "salt": salt.hex()})
    return k, params
