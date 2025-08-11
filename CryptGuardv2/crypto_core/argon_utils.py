"""
Argon2 utilities and calibration.
"""
from __future__ import annotations
import json, psutil, os, time
from pathlib import Path
from argon2.low_level import hash_secret_raw, Type
from .secure_bytes   import SecureBytes
from .key_obfuscator import KeyObfuscator
import logging

from .security_warning import warn

logger = logging.getLogger("crypto_core")

from .paths import BASE_DIR
CALIB_PATH = BASE_DIR / "argon_calib.json"
_KEY_LEN = 32
_DEFAULT = dict(time_cost=3, memory_cost=128*1024, parallelism=4)

# Safety bounds
_MIN_SALT_LEN = 16
_MIN_MEM_KIB = 64 * 1024            # 64 MiB minimum
_MAX_MEM_KIB = 1024 * 1024          # 1 GiB maximum (practical cap)
_MAX_PARALLELISM = 8                # avoid excessive lanes

def _available_ram() -> int:
    try:
        return int(psutil.virtual_memory().available)
    except Exception:
        return 512 * 1024 * 1024  # 512 MiB fallback

def _sanitize_params(p: dict) -> dict:
    """
    Clamp and validate Argon2 parameters to reasonable bounds.
    """
    try:
        time_cost = int(p.get("time_cost", _DEFAULT["time_cost"]))
        memory_cost = int(p.get("memory_cost", _DEFAULT["memory_cost"]))
        parallelism = int(p.get("parallelism", _DEFAULT["parallelism"]))
    except Exception:
        return dict(_DEFAULT)

    time_cost = max(1, time_cost)
    memory_cost = max(_MIN_MEM_KIB, min(memory_cost, _MAX_MEM_KIB))
    parallelism = max(1, min(parallelism, _MAX_PARALLELISM))

    # Ensure enough memory per lane (Argon2 requirement approximation)
    if memory_cost < 8 * parallelism:
        parallelism = max(1, memory_cost // 8) or 1

    return {"time_cost": time_cost, "memory_cost": memory_cost, "parallelism": parallelism}

def generate_key_from_password(
    pwd_sb: SecureBytes,
    salt: bytes,
    params: dict | None = None,
):
    """
    Deriva chave de 32 B via Argon2id.  
    Retorna **KeyObfuscator** (já mascarado) + dicionário de parâmetros usados.

    Nota: a limpeza (pwd_sb.clear()) é agora responsabilidade do chamador,
    garantindo que o objeto não seja reutilizado após ter sido zerado.
    """
    p = dict(params or load_calibrated_params() or _DEFAULT)
    p = _sanitize_params(p)
    if p["time_cost"] < 2:
        warn("Argon2 time_cost MUITO baixo (<2) – segurança reduzida", sev="MEDIUM")

    # Validate salt
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < _MIN_SALT_LEN:
        raise ValueError("salt must be at least 16 bytes")

    need = p["memory_cost"]*1024
    if need > _available_ram()//2:
        warn("Reduzindo memory_cost para caber em RAM", sev="LOW")
        while need > _available_ram()//2 and p["memory_cost"]>8*1024:
            p["memory_cost"]//=2; need=p["memory_cost"]*1024
        # Re-adjust lanes if memory reduced too much
        if p["memory_cost"] < 8 * p["parallelism"]:
            p["parallelism"] = max(1, p["memory_cost"] // 8) or 1

    raw = hash_secret_raw(
        secret=pwd_sb.to_bytes(),
        salt=salt,
        time_cost=p["time_cost"],
        memory_cost=p["memory_cost"],
        parallelism=p["parallelism"],
        hash_len=_KEY_LEN,
        type=Type.ID,
    )
    # Minimize lifetime of the raw key bytes
    sec = SecureBytes(raw)
    del raw
    obf = KeyObfuscator(sec)
    obf.obfuscate()
    return obf, p

def calibrate_kdf(target_time: float = 1.0) -> dict:
    """
    Mira ~target_time s ajustando time_cost; memory_cost em KiB.
    Salva em CALIB_PATH e retorna dict {time_cost, memory_cost, parallelism}.
    """
    # use ~50% da RAM disponível, com limites práticos
    mem_bytes = max(_MIN_MEM_KIB * 1024, int(_available_ram() * 0.5))
    mem_bytes = min(mem_bytes, _MAX_MEM_KIB * 1024)
    memory_cost = mem_bytes // 1024  # KiB
    parallelism = min(max(1, os.cpu_count() or 1), _MAX_PARALLELISM)
    if memory_cost < 8 * parallelism:
        parallelism = max(1, memory_cost // 8)

    tc = 1
    while True:
        start = time.perf_counter()
        try:
            hash_secret_raw(
                secret=b"bench", salt=b"\x00" * 16,
                time_cost=tc, memory_cost=memory_cost, parallelism=parallelism,
                hash_len=32, type=Type.ID
            )
        except (MemoryError, ValueError):
            # Reduce memory if the chosen setting does not fit
            if memory_cost > _MIN_MEM_KIB:
                memory_cost = max(_MIN_MEM_KIB, memory_cost // 2)
                if memory_cost < 8 * parallelism:
                    parallelism = max(1, memory_cost // 8)
                continue
            else:
                raise
        elapsed = time.perf_counter() - start
        if elapsed >= target_time or tc >= 20:
            break
        tc += 1

    params = _sanitize_params({"time_cost": tc, "memory_cost": memory_cost, "parallelism": parallelism})
    CALIB_PATH.parent.mkdir(parents=True, exist_ok=True)
    CALIB_PATH.write_text(json.dumps(params))
    logger.info("Argon2 calibrado e salvo: %s", params)
    return params

def load_calibrated_params():
    """Load calibrated parameters from file."""
    try:
        if CALIB_PATH.exists():
            loaded = json.loads(CALIB_PATH.read_text())
            return _sanitize_params(loaded)
    except Exception:
        pass
    return None
