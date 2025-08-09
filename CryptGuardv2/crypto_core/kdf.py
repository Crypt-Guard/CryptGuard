"""Key derivation functions with dict parameter support for CG2 format."""
from __future__ import annotations
import argon2
from .config import SecurityProfile, ARGON_PARAMS

SecureBytes = bytes
META_ARGON_PARAMS = {
    "name": "argon2id",
    "salt": "deadbeef",
    "time_cost": 2,
    "memory_cost": 512,
    "parallelism": 2
}

def generate_key_from_password(pswd_sb: SecureBytes, salt: bytes, params: dict) -> tuple:
    # Using derive_key as a placeholder for key derivation
    return derive_key(pswd_sb, params), None

def derive_key(password: bytes, salt_or_params, profile: SecurityProfile = None) -> bytes:
    """
    Derive key using Argon2id.
    
    Args:
        password: Raw password bytes
        salt_or_params: Either bytes (salt) or dict with KDF parameters
        profile: Security profile (used when salt_or_params is bytes)
    
    Returns:
        32-byte derived key
    """
    if isinstance(salt_or_params, dict):
        # CG2 format: dict contains all parameters
        params = salt_or_params
        assert params.get("name") == "argon2id"
        salt_hex = params["salt"]
        salt = bytes.fromhex(salt_hex)
        return argon2.low_level.hash_secret_raw(
            password,
            salt,
            time_cost=params["time_cost"],
            memory_cost=params["memory_cost"],
            parallelism=params["parallelism"],
            hash_len=32,
            type=argon2.Type.ID
        )
    else:
        # Legacy format: salt_or_params is raw salt bytes
        return argon2.low_level.hash_secret_raw(
            password,
            salt_or_params,
            time_cost=ARGON_PARAMS["time_cost"],
            memory_cost=ARGON_PARAMS["memory_cost"],
            parallelism=ARGON_PARAMS["parallelism"],
            hash_len=32,
            type=argon2.Type.ID
        )

def derive_meta_key(pswd_sb: SecureBytes, salt: bytes):
    obf, _ = generate_key_from_password(pswd_sb, salt, META_ARGON_PARAMS)
    return obf.deobfuscate()
