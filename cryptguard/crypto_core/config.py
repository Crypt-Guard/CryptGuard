# crypto_core/config.py
"""
Global configuration settings for CryptGuard.
"""

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

# Maximum chunk size to avoid excessive memory usage
MAX_CHUNK_SIZE = 100 * 1024 * 1024  # 100 MB

# New: RS parameters and metadata
RS_PARITY_BYTES = 32              # Reed-Solomon parity bytes by default
META_VERSION = 2                  # current metadata format version
SIGN_METADATA = False             # enable HMAC signature in metadata (optional)

def set_use_rs(value: bool):
    global USE_RS
    USE_RS = value

# NEW: Maximum sub-block size in single-shot mode to allow re-obfuscation
SINGLE_SHOT_SUBCHUNK_SIZE = 1 * 1024 * 1024  # 1 MB, adjustable

# Add settings for different security profiles

# Fast profile (less secure against brute force attacks, but faster)
ARGON_TIME_COST_FAST = 1
ARGON_MEMORY_COST_FAST = 65536  # 64 MB
ARGON_PARALLELISM_FAST = 4

# Balanced profile (default)
ARGON_TIME_COST_BALANCED = 3
ARGON_MEMORY_COST_BALANCED = 131072  # 128 MB
ARGON_PARALLELISM_BALANCED = 4

# Secure profile (slower but more secure)
ARGON_TIME_COST_SECURE = 8
ARGON_MEMORY_COST_SECURE = 262144  # 256 MB
ARGON_PARALLELISM_SECURE = 4

# Current configuration - set to balanced profile
ARGON_TIME_COST = ARGON_TIME_COST_BALANCED
ARGON_MEMORY_COST = ARGON_MEMORY_COST_BALANCED
ARGON_PARALLELISM = ARGON_PARALLELISM_BALANCED
