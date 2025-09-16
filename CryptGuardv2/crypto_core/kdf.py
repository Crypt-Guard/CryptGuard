from __future__ import annotations

# kdf.py — módulo unificado (v5-first + compat)
# - Mantém derive_key_sb / derive_key / derive_meta_key (compat)
# - Adiciona APIs v5: perfis, calibração e JSON canônico (derive_key_v5, etc.)

import base64
import os
import secrets
import time
from dataclasses import dataclass
from typing import Tuple, Literal, Dict, Any, Union

from argon2 import low_level as _argon

from .secure_bytes import SecureBytes
from .fileformat_v5 import canonical_json_bytes

# ---------------------------------------------------------------------------
# Compat "genérico" — Argon2id com dicionário de parâmetros
# ---------------------------------------------------------------------------

def _coerce_salt(params) -> bytes:
    salt = params.get("salt")
    if isinstance(salt, str):
        salt = bytes.fromhex(salt)
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
        raise ValueError("salt must be >=16 bytes")
    return bytes(salt)

def derive_key_sb(password: SecureBytes | bytes | str, params, length: int = 32) -> SecureBytes:
    """Deriva chave Argon2id retornando SecureBytes (modo compat por dicionário)."""
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

def derive_key(password, params, length: int = 32) -> bytes:
    """Compat — retorna bytes. Use derive_key_sb quando possível."""
    sb = derive_key_sb(password, params, length)
    try:
        return bytes(sb.view())
    finally:
        sb.clear()

def derive_meta_key(password, params, length: int = 32) -> bytes:
    """Compat para chamadores antigos (ex.: metadata.py)."""
    return derive_key(password, params, length)

def generate_key_from_password(pswd_sb, salt: bytes, params: dict):
    """Compat p/ argon_utils.generate_key_from_password()."""
    k = derive_key_sb(pswd_sb, {**params, "salt": salt.hex()})
    return k, params

# ---------------------------------------------------------------------------
# v5-first — perfis, calibração e JSON canônico persistido no header
# ---------------------------------------------------------------------------

Password = Union[str, bytes]

@dataclass(frozen=True)
class KDFProfile:
    name: Literal["INTERACTIVE", "SENSITIVE"]
    target_ms: int
    base_mem_mib: int
    parallelism: int

@dataclass(frozen=True)
class Argon2Params:
    time_cost: int  # t
    memory_cost: int  # KiB
    parallelism: int  # p
    salt: bytes  # 32B
    measured_ms: float
    profile: Literal["INTERACTIVE", "SENSITIVE"]

INTERACTIVE = KDFProfile("INTERACTIVE", target_ms=350, base_mem_mib=64, parallelism=1)
SENSITIVE   = KDFProfile("SENSITIVE",   target_ms=700, base_mem_mib=256, parallelism=1)

# Guardrails para calibração v5
MIN_T, MAX_T = 1, 10
MIN_M_KIB, MAX_M_KIB = 16 * 1024, 2 * 1024 * 1024  # 16 MiB .. 2 GiB
MIN_P, MAX_P = 1, 4

def validate_params(t: int, m_kib: int, p: int) -> None:
    if not (MIN_T <= t <= MAX_T):
        raise ValueError("Argon2id time_cost fora de faixa")
    if not (MIN_M_KIB <= m_kib <= MAX_M_KIB):
        raise ValueError("Argon2id memory_cost fora de faixa (KiB)")
    if not (MIN_P <= p <= MAX_P):
        raise ValueError("Argon2id parallelism fora de faixa")

def _cpu_count() -> int:
    try:
        return max(1, os.cpu_count() or 1)
    except Exception:
        return 1

def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(v)))

def calibrate_argon2id(
    target_ms: int = 350,
    base_mem_mib: int = 64,
    parallelism: int = 1,
    password_probe: bytes = b"probe",
) -> Argon2Params:
    """
    Encontra t (1..10) que atinja ~target_ms com memória base (MiB) e p.
    Retorna parâmetros em KiB + salt de 32B e tempo medido.
    """
    p = _clamp(parallelism, MIN_P, MAX_P)
    m_kib = _clamp(base_mem_mib * 1024, MIN_M_KIB, MAX_M_KIB)
    t = MIN_T
    salt = secrets.token_bytes(32)
    measured = 0.0
    while t <= MAX_T:
        start = time.perf_counter()
        _ = _argon.hash_secret_raw(
            password_probe,
            salt,
            time_cost=t,
            memory_cost=m_kib,
            parallelism=p,
            hash_len=32,
            type=_argon.Type.ID,
        )
        measured = (time.perf_counter() - start) * 1000.0
        if measured >= target_ms:
            break
        t += 1
    validate_params(t, m_kib, p)
    profile = "INTERACTIVE" if target_ms <= 450 else "SENSITIVE"
    return Argon2Params(t, m_kib, p, salt, round(measured, 1), profile)

def _to_bytes_password(pw: Password) -> bytes:
    if isinstance(pw, bytes):
        return pw
    if isinstance(pw, str):
        return pw.encode("utf-8")
    raise TypeError("password deve ser str ou bytes")

def _argon_version_str() -> str:
    try:
        return str(getattr(_argon, "ARGON2_VERSION", "20190702"))
    except Exception:
        return "20190702"

def _derive_once(pwd: bytes, salt: bytes, t: int, m_kib: int, p: int, length: int = 32) -> bytes:
    if _argon is None:
        raise RuntimeError("Argon2 library not available. Install 'argon2-cffi'.")
    return _argon.hash_secret_raw(
        secret=pwd, salt=salt,
        time_cost=int(t), memory_cost=int(m_kib), parallelism=int(p),
        hash_len=length, type=_argon.Type.ID
    )

def _build_kdf_json(params: Argon2Params, salt: bytes, profile: KDFProfile) -> bytes:
    obj = {
        "algo": "argon2id",
        "t": int(params.time_cost),
        "m": int(params.memory_cost),   # KiB
        "p": int(params.parallelism),
        "salt_hex": salt.hex(),
        "profile": profile.name,
        "measured_ms": float(params.measured_ms),
    }
    return canonical_json_bytes(obj)

def _parse_kdf_json(kdf_json: bytes) -> Dict[str, Any]:
    import json
    obj = json.loads(kdf_json.decode("utf-8"))
    required = {"algo", "t", "m", "p", "salt_hex"}
    if not required.issubset(set(obj.keys())):
        raise ValueError("KDF_JSON incompleto")
    if obj.get("algo") != "argon2id":
        raise ValueError("KDF_JSON algo não suportado")
    validate_params(int(obj["t"]), int(obj["m"]), int(obj["p"]))
    salt = bytes.fromhex(str(obj["salt_hex"]))
    if len(salt) != 32:
        raise ValueError("salt deve ter 32 bytes (hex)")
    obj["_salt_bytes"] = salt
    return obj

def derive_key_and_params(password: Password, profile: Literal["INTERACTIVE", "SENSITIVE"] = "INTERACTIVE") -> Tuple[bytes, bytes]:
    """Deriva (key32, kdf_params_json_bytes) calibrado por perfil; JSON canônico (pronto p/ AAD)."""
    pw = _to_bytes_password(password)
    prof = INTERACTIVE if profile == "INTERACTIVE" else SENSITIVE
    params = calibrate_argon2id(
        target_ms=prof.target_ms,
        base_mem_mib=prof.base_mem_mib,
        parallelism=prof.parallelism,
        password_probe=b"probe",
    )
    salt = secrets.token_bytes(32)
    key32 = _derive_once(pw, salt, params.time_cost, params.memory_cost, params.parallelism, 32)
    kdf_json = _build_kdf_json(params, salt, prof)
    return key32, kdf_json

def derive_key_from_params(password: Password, kdf_params_json: bytes) -> bytes:
    """Re-deriva a mesma chave de 32B usando parâmetros persistidos (JSON canônico)."""
    pw = _to_bytes_password(password)
    obj = _parse_kdf_json(kdf_params_json)
    return _derive_once(pw, obj["_salt_bytes"], int(obj["t"]), int(obj["m"]), int(obj["p"]), 32)

# Aliases v5 (mantidos para compat com chamadores que usam esses nomes)
def derive_key_v5(password: bytes | str, kdf_profile: str, *, target_ms: int | None = None) -> Tuple[bytes, bytes]:
    """
    Mantido por compat: calibra e retorna (key32, params_json).
    Se target_ms vier definido, deixamos a calibração do calibrate_argon2id decidir.
    """
    prof = "INTERACTIVE" if str(kdf_profile).upper().startswith("INTER") else "SENSITIVE"
    return derive_key_and_params(password, profile=prof)  # calibração já considera perfil

def derive_key_from_params_json(password: bytes | str, kdf_params_json: bytes) -> bytes:
    return derive_key_from_params(password, kdf_params_json)

__all__ = [
    # compat
    "derive_key_sb", "derive_key", "derive_meta_key", "generate_key_from_password",
    # v5
    "KDFProfile", "INTERACTIVE", "SENSITIVE", "Argon2Params",
    "derive_key_and_params", "derive_key_from_params",
    "derive_key_v5", "derive_key_from_params_json",
    "calibrate_argon2id", "validate_params",
]