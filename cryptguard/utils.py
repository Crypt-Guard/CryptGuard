# utils.py
"""
Utility functions: clearing screen, generating unique filenames, ephemeral tokens, etc.
"""

import os
import datetime
import secrets
import subprocess


def clear_screen() -> None:
    """
    Clears the terminal screen on Windows or Unix-based systems.
    If the command is not available, it may fail silently.
    """
    try:
        subprocess.call('cls' if os.name == 'nt' else 'clear', shell=True)
    except Exception:
        # Fallback: do nothing
        pass


def generate_ephemeral_token(n_bits: int = 128) -> str:
    """
    Returns a hex token with n_bits of entropy.
    """
    num = int.from_bytes(secrets.token_bytes((n_bits + 7) // 8), 'big')
    return hex(num)[2:]


def generate_random_number(n_bits: int) -> int:
    """
    Generates a pseudo-random integer with n_bits of entropy using secrets.token_bytes.
    """
    random_bytes = secrets.token_bytes((n_bits + 7) // 8)
    number = int.from_bytes(random_bytes, 'big')
    excess = (len(random_bytes) * 8 - n_bits)
    if excess > 0:
        number >>= excess
    return number


def generate_unique_filename(prefix: str, extension: str = ".enc") -> str:
    """
    Generates a unique filename with prefix, timestamp, and random component.
    Ensures prefix does not contain path separators, etc.
    """
    # Sanitizar prefixo minimamente
    prefix = prefix.replace("/", "_").replace("\\", "_").replace("..", "_")

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    random_component = hex(generate_random_number(64))[2:]
    return f"{prefix}_{timestamp}_{random_component}{extension}"
