"""
Argon2 utilitário com calibração opcional (75 % da RAM disponível).
"""
from __future__ import annotations
import json, math, psutil, secrets, os, time
from pathlib import Path
from argon2.low_level import hash_secret_raw, Type
import argon2
from .secure_bytes   import SecureBytes
from .key_obfuscator import KeyObfuscator
from .logger         import logger
from .security_warning import warn

CALIB_PATH = Path.home()/".my_encryptor"/"argon_calib.json"
_KEY_LEN = 32
_DEFAULT = dict(time_cost=3, memory_cost=128*1024, parallelism=4)

def _available_ram() -> int: return psutil.virtual_memory().available

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

def calibrate_kdf(target_time=1.0):
    """Calibra os parâmetros do KDF para o tempo alvo especificado e salva no arquivo"""
    memory_cost = 65536  # Base ajustável
    parallelism = os.cpu_count() or 4
    time_cost = 1
    
    for tc in range(1, 20):  # Aumentei range para melhor precisão
        start = time.time()
        argon2.hash_password_raw(
            password=b'test_password',
            salt=b'test_salt_16bytes',
            time_cost=tc,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            type=argon2.Type.ID
        )
        elapsed = time.time() - start
        if elapsed >= target_time:
            break
    
    params = {"time_cost": tc, "memory_cost": memory_cost, "parallelism": parallelism}
    CALIB_PATH.parent.mkdir(parents=True, exist_ok=True)
    CALIB_PATH.write_text(json.dumps(params))
    logger.info("Argon2 calibrado e salvo: %s", params)
    return params

def load_calibrated_params():
    if CALIB_PATH.exists():
        try: return json.loads(CALIB_PATH.read_text())
        except Exception: pass
    return None
