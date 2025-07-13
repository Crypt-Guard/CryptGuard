"""
Logger com SecureFormatter – remove bytes sensíveis (>12 bytes de hex).
"""
import logging
import os
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Use Windows-compatible path
LOG_PATH = Path(os.getenv("LOCALAPPDATA", Path.home())) / "CryptGuard" / "crypto.log"

# Ensure directory and file exist
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
LOG_PATH.touch(exist_ok=True)        # <-- cria arquivo vazio se não existir

_HEX_RE = re.compile(r"0x[a-fA-F0-9]{12,}")

class SecureFormatter(logging.Formatter):
    def format(self, record):
        msg = super().format(record)
        # oculta sequências grandes de hex
        return _HEX_RE.sub("<hex-omitted>", msg)

_fmt = "%(asctime)s | %(levelname)s | %(message)s"
handler = RotatingFileHandler(LOG_PATH, maxBytes=5_000_000, backupCount=3)
handler.setFormatter(SecureFormatter(_fmt))

logger = logging.getLogger("crypto_core")
logger.setLevel(logging.INFO)
logger.addHandler(handler)
logger.propagate = False

def get_logger():
    return logger

# Configuração do logger (se não existir)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

def warn_critical(message: str):
    """Registra uma mensagem de aviso crítico"""
    logger.critical(message)

# Log initial startup message
logger.info("=== CryptGuard iniciado ===")
