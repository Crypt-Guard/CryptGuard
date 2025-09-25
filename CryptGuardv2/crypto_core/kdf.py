from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any, Literal, Union

from argon2 import low_level as _argon

from .fileformat_v5 import canonical_json_bytes
from .secure_bytes import SecureBytes

# ---------------------------------------------------------------------------
# Validação Centralizada (RFC 9106)
# ---------------------------------------------------------------------------

# Guardrails para calibração v5 e validação geral
MIN_T, MAX_T = 1, 10
MIN_M_KIB, MAX_M_KIB = 16 * 1024, 2 * 1024 * 1024  # 16 MiB .. 2 GiB
MIN_P, MAX_P = 1, 4
MIN_SALT_LEN = 16
ARGON2_VERSION = 0x13 # 19 em decimal

def _validate_argon2id_rfc9106(t: int, m_kib: int, p: int, salt_len: int) -> None:
    """Valida parâmetros Argon2id contra as recomendações da RFC 9106."""
    if not (MIN_T <= t <= MAX_T):
        raise ValueError(f"Argon2id time_cost (t={t}) fora da faixa segura [{MIN_T}-{MAX_T}]")
    if not (MIN_M_KIB <= m_kib <= MAX_M_KIB):
        raise ValueError(f"Argon2id memory_cost (m={m_kib} KiB) fora da faixa segura [{MIN_M_KIB}-{MAX_M_KIB}]")
    if not (MIN_P <= p <= MAX_P):
        raise ValueError(f"Argon2id parallelism (p={p}) fora da faixa segura [{MIN_P}-{MAX_P}]")
    if salt_len < MIN_SALT_LEN:
        raise ValueError(f"Salt (len={salt_len}) deve ter no mínimo {MIN_SALT_LEN} bytes")
    if m_kib < 8 * p:
        raise ValueError(f"Argon2id memory_cost (m={m_kib} KiB) deve ser >= 8 * parallelism (p={p})")

    lib_version = getattr(_argon, "ARGON2_VERSION", None)
    if lib_version != ARGON2_VERSION:
        # Usamos UserWarning em vez de RuntimeError para não quebrar a aplicação se a lib for atualizada.
        import warnings
        warnings.warn(f"Versão da biblioteca Argon2 (0x{lib_version:x}) não é a recomendada (0x{ARGON2_VERSION:x})", UserWarning)

# ---------------------------------------------------------------------------
# Funções de Compatibilidade
# ---------------------------------------------------------------------------

def _coerce_salt(params: dict) -> bytes:
    salt = params.get("salt")
    if isinstance(salt, str):
        salt = bytes.fromhex(salt)
    if not isinstance(salt, bytes | bytearray):
        raise TypeError("Salt deve ser bytes ou uma string hexadecimal")
    return bytes(salt)

def derive_key_sb(password: SecureBytes | bytes | str, params: dict, length: int = 32) -> SecureBytes:
    """Deriva chave Argon2id (compat) retornando SecureBytes, com validação completa."""
    if isinstance(password, str):
        pwd_sb = SecureBytes(password.encode())
    elif isinstance(password, SecureBytes):
        pwd_sb = password
    elif isinstance(password, bytes | bytearray):
        pwd_sb = SecureBytes(bytes(password))
    else:
        raise TypeError(f"Password must be str, bytes or SecureBytes, not {type(password)}")

    salt = _coerce_salt(params)
    t = int(params.get("time_cost", 2))
    m_kib = int(params.get("memory_cost", 64 * 1024))
    p = int(params.get("parallelism", 2))

    _validate_argon2id_rfc9106(t, m_kib, p, len(salt))

    out: bytes | None = None
    def _derive(pwd_bytes: bytes):
        nonlocal out
        out = _argon.hash_secret_raw(pwd_bytes, salt, t, m_kib, p, length, _argon.Type.ID)

    pwd_sb.with_bytes(_derive)
    return SecureBytes(out)

def derive_key(password, params, length: int = 32) -> bytes:
    sb = derive_key_sb(password, params, length)
    try:
        return bytes(sb.view())
    finally:
        sb.clear()

def derive_meta_key(password, params, length: int = 32) -> bytes:
    return derive_key(password, params, length)

def generate_key_from_password(pswd_sb, salt: bytes, params: dict):
    k = derive_key_sb(pswd_sb, {**params, "salt": salt.hex()})
    return k, params

# ---------------------------------------------------------------------------
# APIs v5 (Perfis, Calibração, JSON Canônico)
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
    time_cost: int
    memory_cost: int # KiB
    parallelism: int
    salt: bytes
    measured_ms: float
    profile: Literal["INTERACTIVE", "SENSITIVE"]

INTERACTIVE = KDFProfile("INTERACTIVE", target_ms=350, base_mem_mib=64, parallelism=1)
SENSITIVE = KDFProfile("SENSITIVE", target_ms=700, base_mem_mib=256, parallelism=1)

def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(v)))

def calibrate_argon2id(
    target_ms: int = 350, base_mem_mib: int = 64, parallelism: int = 1, password_probe: bytes = b"probe"
) -> Argon2Params:
    p = _clamp(parallelism, MIN_P, MAX_P)
    m_kib = _clamp(base_mem_mib * 1024, MIN_M_KIB, MAX_M_KIB)
    t = MIN_T
    salt = secrets.token_bytes(32)
    measured = 0.0

    _validate_argon2id_rfc9106(t, m_kib, p, len(salt))

    while t <= MAX_T:
        start = time.perf_counter()
        _ = _argon.hash_secret_raw(password_probe, salt, t, m_kib, p, 32, _argon.Type.ID)
        measured = (time.perf_counter() - start) * 1000.0
        if measured >= target_ms:
            break
        t += 1

    profile = "INTERACTIVE" if target_ms <= 450 else "SENSITIVE"
    return Argon2Params(t, m_kib, p, salt, round(measured, 1), profile)

def _to_bytes_password(pw: Password) -> bytes:
    if isinstance(pw, bytes): return pw
    if isinstance(pw, str): return pw.encode("utf-8")
    raise TypeError("password deve ser str ou bytes")

def _derive_once(pwd: bytes, salt: bytes, t: int, m_kib: int, p: int, length: int = 32) -> bytes:
    _validate_argon2id_rfc9106(t, m_kib, p, len(salt))
    return _argon.hash_secret_raw(secret=pwd, salt=salt, time_cost=t, memory_cost=m_kib, parallelism=p, hash_len=length, type=_argon.Type.ID)

def _parse_kdf_json(kdf_json: bytes) -> dict[str, Any]:
    obj = json.loads(kdf_json.decode("utf-8"))
    required = {"algo", "t", "m", "p", "salt_hex"}
    if not required.issubset(obj.keys()) or obj.get("algo") != "argon2id":
        raise ValueError("KDF_JSON inválido ou não suportado")

    salt = bytes.fromhex(str(obj["salt_hex"]))
    _validate_argon2id_rfc9106(int(obj["t"]), int(obj["m"]), int(obj["p"]), len(salt))

    obj["_salt_bytes"] = salt
    return obj

def derive_key_and_params(password: Password, profile: Literal["INTERACTIVE", "SENSITIVE"] = "INTERACTIVE") -> tuple[bytes, bytes]:
    pw = _to_bytes_password(password)
    prof = INTERACTIVE if profile == "INTERACTIVE" else SENSITIVE
    params = calibrate_argon2id(prof.target_ms, prof.base_mem_mib, prof.parallelism)
    salt = secrets.token_bytes(32)
    key32 = _derive_once(pw, salt, params.time_cost, params.memory_cost, params.parallelism, 32)

    obj = {
        "algo": "argon2id", "t": params.time_cost, "m": params.memory_cost, "p": params.parallelism,
        "salt_hex": salt.hex(), "profile": profile, "measured_ms": params.measured_ms,
    }
    kdf_json = canonical_json_bytes(obj)
    return key32, kdf_json

def derive_key_from_params(password: Password, kdf_params_json: bytes) -> bytes:
    pw = _to_bytes_password(password)
    obj = _parse_kdf_json(kdf_params_json)
    return _derive_once(pw, obj["_salt_bytes"], int(obj["t"]), int(obj["m"]), int(obj["p"]), 32)

# Aliases mantidos para compatibilidade
derive_key_v5 = derive_key_and_params
derive_key_from_params_json = derive_key_from_params

__all__ = [
    "derive_key_sb", "derive_key", "derive_meta_key", "generate_key_from_password",
    "KDFProfile", "INTERACTIVE", "SENSITIVE", "Argon2Params", "derive_key_and_params",
    "derive_key_from_params", "derive_key_v5", "derive_key_from_params_json",
    "calibrate_argon2id", "_validate_argon2id_rfc9106",
]