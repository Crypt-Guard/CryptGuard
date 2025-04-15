# utils.py
"""
Utility functions: clearing screen, generating unique filenames, ephemeral tokens, etc.
"""

import os
import datetime
import secrets
import subprocess

def clear_screen() -> None:
    try:
        subprocess.call('cls' if os.name == 'nt' else 'clear', shell=True)
    except Exception:
        pass

def generate_ephemeral_token(n_bits: int = 128) -> str:
    num = int.from_bytes(secrets.token_bytes((n_bits + 7) // 8), 'big')
    return hex(num)[2:]

def generate_random_number(n_bits: int) -> int:
    random_bytes = secrets.token_bytes((n_bits + 7) // 8)
    number = int.from_bytes(random_bytes, 'big')
    excess = (len(random_bytes) * 8 - n_bits)
    if excess > 0:
        number >>= excess
    return number

def generate_unique_filename(prefix: str, extension: str = ".enc") -> str:
    prefix = prefix.replace("/", "_").replace("\\", "_").replace("..", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    random_component = hex(generate_random_number(64))[2:]
    return f"{prefix}_{timestamp}_{random_component}{extension}"
