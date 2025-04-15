# crypto_core/argon_utils.py
"""
Functions for key derivation using Argon2id.
"""

from argon2.low_level import hash_secret_raw, Type
from crypto_core.config import DEFAULT_ARGON_PARAMS
from crypto_core.secure_bytes import SecureBytes
from crypto_core.key_obfuscator import KeyObfuscator

def generate_key_from_password(password, salt: bytes,
                               params: dict, extra: bytes = None) -> KeyObfuscator:
    import math

    if isinstance(password, SecureBytes):
        secret = password.to_bytes() if extra is None else password.to_bytes() + extra
    else:
        secret = bytes(password) if extra is None else bytes(password) + extra

    time_cost = params["time_cost"]
    memory_cost = params["memory_cost"]
    parallelism = params["parallelism"]

    while True:
        try:
            key_raw = hash_secret_raw(
                secret=secret,
                salt=salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=32,
                type=Type.ID
            )
            break
        except MemoryError:
            new_val = memory_cost // 2
            if new_val < 8192:
                raise MemoryError("Argon2 memory_cost too high, fallback exhausted.")
            memory_cost = new_val
            print(f"Warning: Argon2 memory_cost reduced to {memory_cost} - retrying key derivation...")
    
    secret = None

    derived_key = SecureBytes(key_raw)
    
    key_obf = KeyObfuscator(derived_key)
    key_obf.obfuscate()
    
    derived_key.clear()
    
    return key_obf


def get_argon2_parameters_for_encryption() -> dict:
    return DEFAULT_ARGON_PARAMS
