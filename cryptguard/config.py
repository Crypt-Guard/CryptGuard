# config.py
"""
Global configuration settings for CryptGuard.
"""

import os

CHUNK_SIZE = 1024 * 1024  # 1 MB default chunk size
STREAMING_THRESHOLD = 10 * 1024 * 1024  # 10 MB threshold for streaming mode

MAX_ATTEMPTS = 5  # Maximum password attempts before blocking

META_SALT_SIZE = 16  # bytes for metadata salt

# Default Argon2id parameters for file encryption
DEFAULT_ARGON_PARAMS = {
    "time_cost": 4,
    "memory_cost": 102400,  # ~100 MB
    "parallelism": 2
}

# Argon2id parameters for metadata encryption
META_ARGON_PARAMS = {
    "time_cost": 4,
    "memory_cost": 102400,
    "parallelism": 2
}

# Flag to enable or disable Reed-Solomon error correction
USE_RS = True

# Limite máximo de chunk para evitar uso exagerado de memória
MAX_CHUNK_SIZE = 100 * 1024 * 1024  # 100 MB

def set_use_rs(value: bool):
    """
    Dynamically set whether Reed-Solomon correction is used.
    """
    global USE_RS
    USE_RS = value
