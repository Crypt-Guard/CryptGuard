"""
Logger com SecureFormatter – remove bytes sensíveis (hex + Base64).
"""
import logging
import os
import re
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Use Windows-compatible path
LOG_PATH = Path(os.getenv("LOCALAPPDATA", Path.home())) / "CryptGuard" / "crypto.log"

# Ensure directory and file exist
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
LOG_PATH.touch(exist_ok=True)

# ① Padrões de dados sensíveis
_SENSITIVE_RE = re.compile(
    r"""
    (?:0x)?[0-9A-Fa-f]{16,}      # hex longo, com/sem 0x (≥64 bits)
  | [A-Za-z0-9+/]{24,}={0,2}     # Base64 (≥18 bytes ≈128 bits)
  """,
    re.VERBOSE,
)

class SecureFormatter(logging.Formatter):
    def format(self, record):
        msg = super().format(record)
        # ② mascara segredos antes de gravar
        return _SENSITIVE_RE.sub("<redacted>", msg)

# ③ configuração de logger
_fmt = "%(asctime)s | %(levelname)s | %(message)s"
handler = RotatingFileHandler(LOG_PATH, maxBytes=5_000_000, backupCount=3)
handler.setFormatter(SecureFormatter(_fmt))

logger = logging.getLogger("crypto_core")
logger.setLevel(logging.INFO if os.getenv("ENV") != "prod" else logging.WARNING)
logger.addHandler(handler)
logger.propagate = False

# opcional: imprimir no stderr em modo debug
if os.getenv("CG_DEBUG"):
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(SecureFormatter("%(levelname)s: %(message)s"))
    logger.addHandler(sh)

def get_logger():
    return logger

def warn_critical(message: str):
    """Registra uma mensagem de aviso crítico"""
    logger.critical(message)

# Log initial startup message
logger.info("=== CryptGuard iniciado ===")
