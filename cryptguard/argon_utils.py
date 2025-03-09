# argon_utils.py

from argon2.low_level import hash_secret_raw, Type
from config import DEFAULT_ARGON_PARAMS

def generate_key_from_password(password: bytearray, salt: bytes, params: dict, extra: bytes = None):
    """
    Derives a 32-byte key using Argon2id, returning it as a bytearray.
    If 'extra' is provided, it is concatenated to the password for key derivation,
    allowing additional factors (e.g., ephemeral token) to be incorporated.
    """
    secret = bytes(password) if extra is None else bytes(password) + extra
    key_raw = hash_secret_raw(
        secret=secret,
        salt=bytes(salt),
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"],
        hash_len=32,
        type=Type.ID
    )
    return bytearray(key_raw)

def get_argon2_parameters_for_encryption():
    """
    Returns the default Argon2id parameters for encryption.
    Note: Customization should be handled in the UI layer.
    """
    return DEFAULT_ARGON_PARAMS
