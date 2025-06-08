# crypto_core/argon_utils.py
"""
Functions for key derivation using Argon2id.
"""

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import psutil

from crypto_core.config import DEFAULT_ARGON_PARAMS
from crypto_core.secure_bytes import SecureBytes
from crypto_core.key_obfuscator import KeyObfuscator
from typing import Tuple


def validate_system_resources(params: dict) -> None:
    """Validate that the system has enough RAM for Argon2."""
    required_ram = params["memory_cost"] * 1024
    available = psutil.virtual_memory().available
    if required_ram > available * 0.8:
        raise MemoryError(
            f"RAM insuficiente: {required_ram//1024//1024} MiB requeridos, "
            f"{available//1024//1024} MiB dispon\xEDveis"
        )

def generate_key_from_password(
    password,
    salt: bytes,
    params: dict,
    extra: bytes = None,
) -> Tuple[KeyObfuscator, dict]:
    """Derive a key from password returning the KeyObfuscator and params used."""

    validate_system_resources(params)

    actual_params = params.copy()

    if isinstance(password, SecureBytes):
        secret = password.to_bytes() if extra is None else password.to_bytes() + extra
    else:
        secret = bytes(password) if extra is None else bytes(password) + extra

    time_cost = actual_params["time_cost"]
    memory_cost = actual_params["memory_cost"]
    parallelism = actual_params["parallelism"]

    while True:
        try:
            master_key = hash_secret_raw(
                secret=secret,
                salt=salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=32,
                type=Type.ID,
            )

            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=None,
                info=b"CryptGuard-v3-key-derivation",
            )
            expanded = hkdf.derive(master_key)

            cipher_key = SecureBytes(expanded[:32])
            key_obf = KeyObfuscator(cipher_key)
            key_obf.obfuscate()

            master_key_arr = bytearray(master_key)
            for i in range(len(master_key_arr)):
                master_key_arr[i] = 0
            exp_arr = bytearray(expanded)
            for i in range(len(exp_arr)):
                exp_arr[i] = 0
            cipher_key.clear()

            actual_params["memory_cost"] = memory_cost

            break
        except MemoryError:
            new_val = memory_cost // 2
            if new_val < 8192:
                raise MemoryError(
                    f"Sistema sem recursos suficientes. Requer pelo menos {memory_cost//1024} MiB de RAM livre."
                )
            memory_cost = new_val
            actual_params["memory_cost"] = memory_cost
            print(f"Reduzindo memory_cost para {memory_cost} KiB")

    if isinstance(secret, (bytes, bytearray)):
        secret_arr = bytearray(secret)
        for i in range(len(secret_arr)):
            secret_arr[i] = 0

    return key_obf, actual_params


def get_argon2_parameters_for_encryption() -> dict:
    return DEFAULT_ARGON_PARAMS
