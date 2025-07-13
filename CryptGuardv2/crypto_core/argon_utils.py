"""
Argon2 utilitário com calibração opcional (75 % da RAM disponível).
"""
from __future__ import annotations
import json, math, psutil, secrets
from pathlib import Path
from argon2.low_level import hash_secret_raw, Type
from .secure_bytes   import SecureBytes
from .key_obfuscator import KeyObfuscator
from .logger         import logger
from .security_warning import warn

CALIB_PATH = Path.home()/".my_encryptor"/"argon_calib.json"
_KEY_LEN = 32
_DEFAULT = dict(time_cost=3, memory_cost=128*1024, parallelism=4)

def _available_ram() -> int: return psutil.virtual_memory().available

def generate_key_from_password(pswd_sb:SecureBytes, salt:bytes, params:dict|None=None):
    p = dict(params or load_calibrated_params() or _DEFAULT)
    need = p["memory_cost"]*1024
    if need > _available_ram()//2:
        warn("Reduzindo memory_cost para caber em RAM", sev="LOW")
        while need > _available_ram()//2 and p["memory_cost"]>8*1024:
            p["memory_cost"]//=2; need=p["memory_cost"]*1024

    raw = hash_secret_raw(pswd_sb.to_bytes(), salt, **p, hash_len=_KEY_LEN, type=Type.ID)
    obf = KeyObfuscator(SecureBytes(raw)); obf.obfuscate(); pswd_sb.clear()
    return obf, p

def calibrate_kdf():
    ram = psutil.virtual_memory().total
    target = int(ram*0.75)//1024
    params = {"time_cost":3, "memory_cost":target, "parallelism":4}
    CALIB_PATH.parent.mkdir(parents=True, exist_ok=True)
    CALIB_PATH.write_text(json.dumps(params))
    logger.info("Argon2 calibrado: %s", params)

def load_calibrated_params():
    if CALIB_PATH.exists():
        try: return json.loads(CALIB_PATH.read_text())
        except Exception: pass
    return None
