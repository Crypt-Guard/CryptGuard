"""
Constantes e parâmetros (pode ser sobrescrito por calibração Argon2).
"""
from enum import Enum, auto
import os
import json
import time
from pathlib import Path

class SecurityProfile(Enum):
    FAST     = auto()
    BALANCED = auto()
    SECURE   = auto()

# Esses valores podem ser substituídos em tempo de execução por calibração
ARGON_PARAMS = {
    SecurityProfile.FAST:     dict(time_cost=1, memory_cost=64*1024,  parallelism=4),
    SecurityProfile.BALANCED: dict(time_cost=3, memory_cost=128*1024, parallelism=4),
    SecurityProfile.SECURE:   dict(time_cost=6, memory_cost=256*1024, parallelism=4),
}

META_ARGON_PARAMS   = dict(time_cost=1, memory_cost=32*1024, parallelism=2)
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

# Or in the application directory
# LOG_PATH = Path(__file__).parent.parent / "crypto.log"

def load_calibrated_params():
    """Carrega parâmetros calibrados do arquivo de configuração"""
    config_path = Path(__file__).parent / "calibrated_params.json"
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return ARGON_PARAMS

def calibrate_kdf(target_time=1.0):
    """Calibra os parâmetros do KDF para o tempo alvo especificado"""
    import argon2
    
    # Parâmetros base para calibração
    memory_cost = 65536  # 64 MB
    parallelism = 1
    time_cost = 1
    
    # Testa diferentes valores de time_cost
    for tc in range(1, 10):
        start = time.time()
        argon2.hash_password_raw(
            password=b'test_password',
            salt=b'test_salt_16bytes',
            time_cost=tc,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            type=argon2.Type.ID
        )
        elapsed = time.time() - start
        
        if elapsed >= target_time:
            return {
                'time_cost': tc,
                'memory_cost': memory_cost,
                'parallelism': parallelism
            }
    
    return ARGON_PARAMS

def enable_process_hardening():
    """Habilita proteções de processo quando possível"""
    import os
    import sys
    
    # Exemplo de hardening básico
    if hasattr(os, 'setpriority'):
        try:
            os.setpriority(os.PRIO_PROCESS, 0, 10)  # Baixa prioridade
        except:
            pass
    
    # Outras proteções podem ser adicionadas aqui
    pass
