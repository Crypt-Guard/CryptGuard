# config.py

# General chunk parameters
CHUNK_SIZE = 1024 * 1024  # 1 MB
STREAMING_THRESHOLD = 10 * 1024 * 1024  # 10 MB

# Maximum password attempts
MAX_ATTEMPTS = 5

# Salt size used in metadata
META_SALT_SIZE = 16  # bytes for meta_salt

# Default Argon2id parameters for file encryption
DEFAULT_ARGON_PARAMS = {
    "time_cost": 4,
    "memory_cost": 102400,
    "parallelism": 2
}

# Argon2id parameters for metadata encryption (aligned with file parameters)
META_ARGON_PARAMS = {
    "time_cost": 4,
    "memory_cost": 102400,
    "parallelism": 2
}

# Flag to enable or disable Reed-Solomon encoding (for integrity)
USE_RS = True
