from __future__ import annotations

import os

from argon2 import low_level as _argon


def derive_key(password, params, length: int = 32) -> bytes:
    """Deriva chave via Argon2id (32 bytes por padrão), aceitando password str/bytes e params CG2.

    params deve conter ao menos: {name, salt, time_cost, memory_cost, parallelism}
    - name é ignorado (normalizamos para Argon2id)
    - salt pode vir como hex str ou bytes
    """
    # 1) password sempre bytes
    if isinstance(password, str):
        password = password.encode("utf-8")

    # 2) normaliza params
    if isinstance(params, bytes | bytearray):
        # suporte legado: params é o salt bruto
        salt = bytes(params)
        t = int(os.getenv("CG2_ARGON_T", 3))
        m = int(os.getenv("CG2_ARGON_M", 1024 * 1024))
        p = int(os.getenv("CG2_ARGON_P", os.cpu_count() or 2))
    else:
        # name é aceito mas não altera o tipo (forçamos Argon2id)
        salt_hex = params["salt"] if isinstance(params.get("salt"), str) else params["salt"].hex()
        salt = bytes.fromhex(salt_hex)
        t = int(params.get("time_cost", 3))
        m = int(params.get("memory_cost", 1024 * 1024))
        p = int(params.get("parallelism", os.cpu_count() or 2))

    # 3) Argon2id sempre — usar chamadas POSICIONAIS (API do low_level)
    return _argon.hash_secret_raw(password, salt, t, m, p, length, _argon.Type.ID)

def generate_key_from_password(pswd_sb, salt: bytes, params: dict):
    # Aceita SecureBytes ou bytes
    if hasattr(pswd_sb, "to_bytes"):
        pw = pswd_sb.to_bytes()
    else:
        pw = pswd_sb if isinstance(pswd_sb, bytes | bytearray) else bytes(pswd_sb)
    key = derive_key(pw, {**params, "salt": salt.hex()})
    return key, params


# compat: metadata.py espera derive_meta_key
def derive_meta_key(password, params, length: int = 32) -> bytes:
    return derive_key(password, params, length)
