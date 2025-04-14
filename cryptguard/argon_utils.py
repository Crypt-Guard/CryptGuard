# argon_utils.py
"""
Functions for key derivation using Argon2id.
"""

from argon2.low_level import hash_secret_raw, Type
from config import DEFAULT_ARGON_PARAMS
from secure_bytes import SecureBytes
from key_obfuscator import KeyObfuscator

def generate_key_from_password(password, salt: bytes,
                               params: dict, extra: bytes = None) -> KeyObfuscator:
    """
    Derives a 32-byte key using Argon2id and returns it as a KeyObfuscator object.
    If 'extra' is provided, it is concatenated to 'password' for the derivation.
    May raise MemoryError if the memory_cost is too high for the system.
    
    Args:
        password: bytearray or SecureBytes containing the password
        salt: bytes object for Argon2 salt
        params: dictionary with Argon2 parameters
        extra: optional bytes to concatenate with password
        
    Returns:
        KeyObfuscator: An obfuscated key container that protects the derived key in memory
    
    Agora com fallback caso ocorram MemoryErrors:
    Tenta reduzir pela metade o memory_cost e repetir até um mínimo.
    """
    # Construir o "secret" como bytes imutáveis (limite da API), mas limpar referência depois
    import math

    # Handle both SecureBytes and bytearray inputs
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
            break  # sucesso
        except MemoryError:
            new_val = memory_cost // 2
            if new_val < 8192:
                raise MemoryError("Argon2 memory_cost too high, fallback exhausted.")
            memory_cost = new_val
            print(f"Warning: Argon2 memory_cost reduced to {memory_cost} - retrying key derivation...")
    
    # Limpar referência do secret para não ficar em memória
    secret = None

    # Create a SecureBytes object with the derived key
    derived_key = SecureBytes(key_raw)
    
    # Obfuscate the key immediately
    key_obf = KeyObfuscator(derived_key)
    key_obf.obfuscate()
    
    # Clear the original derived key from memory
    derived_key.clear()
    
    return key_obf


def get_argon2_parameters_for_encryption() -> dict:
    """
    Returns the default Argon2id parameters for encryption.
    """
    return DEFAULT_ARGON_PARAMS
