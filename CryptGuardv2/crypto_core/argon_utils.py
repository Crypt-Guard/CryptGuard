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
import argon2

from .security_warning import warn

logger = logging.getLogger("crypto_core")

CALIB_PATH = Path.home()/".my_encryptor"/"argon_calib.json"
_KEY_LEN = 32
_DEFAULT = dict(time_cost=3, memory_cost=128*1024, parallelism=4)

def _available_ram() -> int:
    try:
        return int(psutil.virtual_memory().available)
    except Exception:
        return 512 * 1024 * 1024  # 512 MiB fallback

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
    if p["time_cost"] < 2:
        warn("Argon2 time_cost MUITO baixo (<2) – segurança reduzida", sev="MEDIUM")
    need = p["memory_cost"]*1024
    if need > _available_ram()//2:
        warn("Reduzindo memory_cost para caber em RAM", sev="LOW")
        while need > _available_ram()//2 and p["memory_cost"]>8*1024:
            p["memory_cost"]//=2; need=p["memory_cost"]*1024

    raw = hash_secret_raw(
        secret=pwd_sb.to_bytes(),
        salt=salt,
        time_cost=p["time_cost"],
        memory_cost=p["memory_cost"],
        parallelism=p["parallelism"],
        hash_len=_KEY_LEN,
        type=Type.ID,
    )
    obf = KeyObfuscator(SecureBytes(raw))
    obf.obfuscate()
    return obf, p

def calibrate_kdf(target_time: float = 1.0) -> dict:
    """
    Mira ~target_time s ajustando time_cost; memory_cost em KiB.
    Salva em CALIB_PATH e retorna dict {time_cost, memory_cost, parallelism}.
    """
    # use ~50–75% da RAM disponível, mas respeite mínimo seguro
    mem_bytes = max(64 * 1024 * 1024, int(_available_ram() * 0.5))  # >=64MiB
    memory_cost = mem_bytes // 1024  # KiB
    parallelism = os.cpu_count() or 4

    tc = 1
    while True:
        start = time.perf_counter()
        hash_secret_raw(
            secret=b"bench", salt=b"\x00" * 16,
            time_cost=tc, memory_cost=memory_cost, parallelism=parallelism,
            hash_len=32, type=Type.ID
        )
        elapsed = time.perf_counter() - start
        if elapsed >= target_time or tc >= 20:
            break
        tc += 1

    params = {"time_cost": tc, "memory_cost": memory_cost, "parallelism": parallelism}
    CALIB_PATH.parent.mkdir(parents=True, exist_ok=True)
    CALIB_PATH.write_text(json.dumps(params))
    logger.info("Argon2 calibrado e salvo: %s", params)
    return params

def load_calibrated_params():
    """Load calibrated parameters from file."""
    try:
        if CALIB_PATH.exists():
            return json.loads(CALIB_PATH.read_text())
    except Exception:
        pass
    return None
