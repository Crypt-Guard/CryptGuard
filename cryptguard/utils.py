# utils.py

import os
import datetime
import secrets
import subprocess

def clear_screen():
    subprocess.call('cls' if os.name == 'nt' else 'clear', shell=True)

def generate_ephemeral_token(n_bits=128):
    """
    Returns a hex token with n_bits of entropy.
    """
    num = int.from_bytes(secrets.token_bytes((n_bits+7)//8), 'big')
    return hex(num)[2:]

def generate_random_number(n_bits):
    """
    Generates a pseudo-random number using secrets.token_bytes.
    """
    random_bytes = secrets.token_bytes((n_bits+7)//8)
    number = int.from_bytes(random_bytes, 'big')
    excess = (len(random_bytes)*8 - n_bits)
    if excess > 0:
        number >>= excess
    return number

def generate_unique_filename(prefix: str, extension: str = ".enc") -> str:
    """
    Generates a unique filename with prefix, timestamp, and a random component.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    random_component = hex(generate_random_number(64))[2:]
    return f"{prefix}_{timestamp}_{random_component}{extension}"
