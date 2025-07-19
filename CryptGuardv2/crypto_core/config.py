"""
Constantes e parâmetros (pode ser sobrescrito por calibração Argon2).
"""
from enum import Enum, auto
import os
import time
from pathlib import Path
import argon2
from .argon_utils import calibrate_kdf
from .process_protection import enable_process_hardening as _apply_full_hardening

class SecurityProfile(Enum):
    FAST     = auto()
    BALANCED = auto()
    SECURE   = auto()

ALGORITHMS = {
    "AES-GCM": {
        "module": "file_crypto_aes_gcm",
        "encrypt": "encrypt_file",
        "decrypt": "decrypt_file",
        "nonce": 16,
    },
    "ChaCha20-Poly1305": {
        "module": "file_crypto_chacha",
        "encrypt": "encrypt_file",
        "decrypt": "decrypt_file",
        "nonce": 12,
    },
    "XChaCha20-Poly1305": {
        "module": "file_crypto_xchacha",
        "encrypt": "encrypt_file",
        "decrypt": "decrypt_file",
        "stream": False,       # streaming usará outro módulo se criar depois
    },
}

# Esses valores podem ser substituídos em tempo de execução por calibração
ARGON_PARAMS = {
    SecurityProfile.FAST:     dict(time_cost=1, memory_cost=64*1024,  parallelism=4),
    SecurityProfile.BALANCED: dict(time_cost=3, memory_cost=128*1024, parallelism=4),
    SecurityProfile.SECURE:   dict(time_cost=6, memory_cost=256*1024, parallelism=4),
}

META_ARGON_PARAMS   = dict(time_cost=2, memory_cost=32*1024, parallelism=2)
DEFAULT_ARGON_PARAMS = ARGON_PARAMS[SecurityProfile.BALANCED]

STREAMING_THRESHOLD       = 100 * 1024 * 1024
CHUNK_SIZE                = 8   * 1024 * 1024
SINGLE_SHOT_SUBCHUNK_SIZE = 1   * 1024 * 1024

USE_RS          = True
RS_PARITY_BYTES = 32
SIGN_METADATA   = True

MAGIC          = b"CGS3"       # bump formato p/ v3
ENC_EXT        = ".enc"
META_EXT       = ".meta"
META_SALT_SIZE = 16

# Log in user's temp directory
LOG_PATH = Path(os.path.expanduser("~")) / "AppData" / "Local" / "CryptGuard" / "crypto.log"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

# Standardized calibration path
CALIB_PATH = Path.home() / ".my_encryptor" / "argon_calib.json"

# Or in the application directory
def enable_process_hardening():
    """Habilita proteções de processo quando possível (usa process_protection.py)."""
    _apply_full_hardening()
    
    # Exemplo de hardening básico
    if hasattr(os, 'setpriority'):
        try:
            os.setpriority(os.PRIO_PROCESS, 0, 10)  # Baixa prioridade
        except:
            pass
    
    # Outras proteções podem ser adicionadas aqui
    pass
