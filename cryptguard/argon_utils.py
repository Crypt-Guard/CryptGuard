# argon_utils.py
"""
Functions for key derivation using Argon2id.
"""

from argon2.low_level import hash_secret_raw, Type
from config import DEFAULT_ARGON_PARAMS

def generate_key_from_password(password: bytearray, salt: bytes,
                               params: dict, extra: bytes = None) -> bytearray:
    """
    Derives a 32-byte key (bytearray) using Argon2id.
    If 'extra' is provided, it is concatenated to 'password' for the derivation.
    May raise MemoryError if the memory_cost is too high for the system.

    Agora com fallback caso ocorram MemoryErrors (exemplo simples):
    - Tenta reduzir pela metade o memory_cost e repetir até um mínimo.
    """
    # Construir o "secret" como bytes imutáveis (limite da API), mas limpar referência depois
    import math

    secret = bytes(password) if extra is None else bytes(password) + extra

    # Fallback de MemoryError: reduzir memory_cost
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
            # Reduz memory_cost pela metade, se possível
            # Param mínimo arbitrário (8192 p.ex.)
            new_val = memory_cost // 2
            if new_val < 8192:
                raise MemoryError("Argon2 memory_cost too high, fallback exhausted.")
            memory_cost = new_val
            print(f"MemoryError: reducing Argon2 memory_cost to {memory_cost} and retrying...")

    # Limpar referência do secret para não ficar em memória
    secret = None

    # Retorna bytearray derivado
    return bytearray(key_raw)


def get_argon2_parameters_for_encryption() -> dict:
    """
    Returns the default Argon2id parameters for encryption.
    """
    return DEFAULT_ARGON_PARAMS
