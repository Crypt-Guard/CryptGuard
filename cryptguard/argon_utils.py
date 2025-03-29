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
    """
    secret = bytes(password) if extra is None else bytes(password) + extra
    key_raw = hash_secret_raw(
        secret=secret,
        salt=salt,
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"],
        hash_len=32,
        type=Type.ID
    )
    return bytearray(key_raw)


def get_argon2_parameters_for_encryption() -> dict:
    """
    Returns the default Argon2id parameters for encryption.
    """
    return DEFAULT_ARGON_PARAMS
