from __future__ import annotations

import base64
import os
import secrets
import time
from dataclasses import dataclass
from typing import Tuple, Literal, Dict, Any, Union

try:
    from argon2 import low_level as _argon
except Exception as e:  # pragma: no cover - surfaced in error messages if missing
    _argon = None  # type: ignore

from .fileformat_v5 import canonical_json_bytes
from .argon_utils import Argon2Params, calibrate_argon2id, validate_params

Password = Union[str, bytes]


@dataclass(frozen=True)
class KDFProfile:
    name: Literal["INTERACTIVE", "SENSITIVE"]
    target_ms: int
    base_mem_mib: int
    parallelism: int


INTERACTIVE = KDFProfile("INTERACTIVE", target_ms=350, base_mem_mib=64, parallelism=1)
SENSITIVE = KDFProfile("SENSITIVE", target_ms=700, base_mem_mib=256, parallelism=1)


def _to_bytes_password(pw: Password) -> bytes:
    if isinstance(pw, bytes):
        return pw
    if isinstance(pw, str):
        return pw.encode("utf-8")
    raise TypeError("password deve ser str ou bytes")


def _build_kdf_json(params: Argon2Params, salt: bytes, profile: KDFProfile) -> bytes:
    obj = {
        "algo": "argon2id",
        "t": int(params.time_cost),
        "m": int(params.memory_cost),  # KiB
        "p": int(params.parallelism),
        "salt_hex": salt.hex(),
        "profile": profile.name,
        "measured_ms": float(params.measured_ms),
    }
    return canonical_json_bytes(obj)


def _parse_kdf_json(kdf_json: bytes) -> Dict[str, Any]:
    import json

    try:
        obj = json.loads(kdf_json.decode("utf-8"))
    except Exception as e:  # pragma: no cover - handled upstream
        raise ValueError("KDF_JSON inválido (UTF-8/JSON)") from e
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


def derive_key_and_params(
    password: Password,
    profile: Literal["INTERACTIVE", "SENSITIVE"] = "INTERACTIVE",
) -> Tuple[bytes, bytes]:
    """
    Deriva uma chave de 32B via Argon2id e retorna (key32, kdf_params_json_bytes).
    O JSON é canônico e pronto para AAD.
    """
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
    """
    Re-deriva a chave de 32B usando os parâmetros persistidos (JSON canônico).
    """
    pw = _to_bytes_password(password)
    obj = _parse_kdf_json(kdf_params_json)
    return _derive_once(pw, obj["_salt_bytes"], int(obj["t"]), int(obj["m"]), int(obj["p"]), 32)


def _cpu_count() -> int:
    try:
        return max(1, os.cpu_count() or 1)
    except Exception:
        return 1


def _argon_version_str() -> str:
    try:
        return str(getattr(_argon, "ARGON2_VERSION", "20190702"))
    except Exception:
        return "20190702"


def _derive_once(pwd: bytes, salt: bytes, t: int, m_kib: int, p: int, length: int = 32) -> bytes:
    if _argon is None:
        raise RuntimeError(
            "Argon2 library not available. Install 'argon2-cffi' to use v5 KDF."
        )
    return _argon.hash_secret_raw(
        secret=pwd,
        salt=salt,
        time_cost=int(t),
        memory_cost=int(m_kib),
        parallelism=int(p),
        hash_len=length,
        type=_argon.Type.ID,
    )


def _calibrate(pwd: bytes, profile: str, target_ms: int | None) -> tuple[int, int, int, int]:
    """
    Returns (t, m_kib, p, observed_ms) tuned to the profile/target.
    """
    prof = profile.upper()
    if prof not in ("INTERACTIVE", "SENSITIVE"):
        raise ValueError("kdf_profile must be 'INTERACTIVE' or 'SENSITIVE'")

    # Defaults per profile
    if prof == "INTERACTIVE":
        tgt = 400 if target_ms is None else int(target_ms)
        tgt = max(250, min(tgt, 750))
        m_kib_try = 64 * 1024
    else:
        tgt = 1800 if target_ms is None else int(target_ms)
        tgt = max(1000, min(tgt, 4000))
        m_kib_try = 1024 * 1024  # 1 GiB

    # p lanes
    p = min(4, _cpu_count())

    # salt for timing (deterministic cost, not secret)
    salt_bench = b"\x00" * 32

    # Ensure memory fits by trying and halving on failure
    m_kib = m_kib_try
    while True:
        try:
            _ = _derive_once(b"bench", salt_bench, 1, m_kib, p, 32)
            break
        except MemoryError:
            m_kib //= 2
            if m_kib < 64 * 1024:
                m_kib = 64 * 1024
                break
        except Exception:
            # If environment is constrained, fall back to safe minimums
            m_kib = max(64 * 1024, m_kib // 2) if m_kib > 64 * 1024 else 64 * 1024
            break

    # Calibrate time cost t
    t = 1
    observed_ms = 0
    for _ in range(32):  # hard cap iterations
        start = time.perf_counter()
        _ = _derive_once(b"bench", salt_bench, t, m_kib, p, 32)
        observed_ms = int((time.perf_counter() - start) * 1000)
        if observed_ms >= tgt:
            break
        t += 1
    if prof == "INTERACTIVE" and t < 2:
        t = 2
    return t, m_kib, p, observed_ms


def derive_key_v5(password: bytes | str, kdf_profile: str, *, target_ms: int | None = None) -> Tuple[bytes, bytes]:
    """
    - Measures hardware and tunes m/t/p to hit target_ms in profile window.
    - Returns (32-byte key, canonical JSON bytes of effective parameters with observed target_ms).
    JSON includes: kdf, profile, salt_b64, t, m, p, target_ms, argon2_version.
    """
    pwd = password.encode() if isinstance(password, str) else password
    if not isinstance(pwd, (bytes, bytearray)):
        raise TypeError("password must be bytes or str")

    t, m_kib, p, observed_ms = _calibrate(pwd, kdf_profile, target_ms)

    salt = secrets.token_bytes(32)
    key = _derive_once(bytes(pwd), salt, t, m_kib, p, 32)

    params = {
        "kdf": "argon2id",
        "profile": kdf_profile.upper(),
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "t": int(t),
        "m": int(m_kib),
        "p": int(p),
        "target_ms": int(observed_ms),
        "argon2_version": _argon_version_str(),
    }
    return key, canonical_json_bytes(params)


def derive_key_from_params_json(password: bytes | str, kdf_params_json: bytes) -> bytes:
    """
    Derives the exact key using persisted (canonical) parameters. No recalibration.
    """
    import json

    pwd = password.encode() if isinstance(password, str) else password
    if not isinstance(pwd, (bytes, bytearray)):
        raise TypeError("password must be bytes or str")
    p = json.loads(kdf_params_json)
    if p.get("kdf") != "argon2id":
        raise ValueError("Unsupported KDF")
    # tolerate both salt_b64 or salt_hex (we emit salt_b64)
    salt_b64 = p.get("salt_b64")
    if salt_b64:
        salt = base64.b64decode(salt_b64)
    else:
        salt_hex = p.get("salt_hex")
        if not salt_hex:
            raise ValueError("Missing salt in KDF params")
        salt = bytes.fromhex(salt_hex)
    t = int(p.get("t", 2))
    m_kib = int(p.get("m", 64 * 1024))
    lanes = int(p.get("p", 2))
    return _derive_once(bytes(pwd), salt, t, m_kib, lanes, 32)


__all__ = [
    "derive_key_v5",
    "derive_key_from_params_json",
    "KDFProfile",
    "INTERACTIVE",
    "SENSITIVE",
    "derive_key_and_params",
    "derive_key_from_params",
]
