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

# Limite máximo de chunk para evitar uso exagerado de memória
MAX_CHUNK_SIZE = 100 * 1024 * 1024  # 100 MB

# Novo: parâmetros de RS e metadados
RS_PARITY_BYTES = 32              # bytes de paridade Reed-Solomon por padrão
META_VERSION = 2                  # versão atual do formato de metadados
SIGN_METADATA = False             # habilitar assinatura HMAC nos metadados (opcional)

def set_use_rs(value: bool):
    global USE_RS
    USE_RS = value

# NOVO: Tamanho máximo de sub-bloco no single-shot para permitir re-obfuscação
SINGLE_SHOT_SUBCHUNK_SIZE = 1 * 1024 * 1024  # 1 MB, ajustável
