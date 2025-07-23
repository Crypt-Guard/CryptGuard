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
    (?:
        (?<=key=)(?:0x)?[0-9A-Fa-f]{16,}      # hex após key=
      | (?<=nonce=)(?:0x)?[0-9A-Fa-f]{16,}    # hex após nonce=
      | (?<=key=)[A-Za-z0-9+/]{24,}={0,2}     # Base64 após key=
      | (?<=nonce=)[A-Za-z0-9+/]{24,}={0,2}   # Base64 após nonce=
      | (?<=password=)[^\s]{8,}               # passwords
      | (?<=pwd=)[^\s]{8,}                    # pwd parameters
    )
    """,
    re.VERBOSE,
)

class SecureFormatter(logging.Formatter):
    def format(self, record):
        msg = super().format(record)
        # ② mascara segredos antes de gravar
        return _SENSITIVE_RE.sub("<redacted>", msg)

# ③ configuração de logger
_fmt = "%(asctime)s | %(levelname)s | %(funcName)s:%(lineno)d | %(message)s"
handler = RotatingFileHandler(LOG_PATH, maxBytes=5_000_000, backupCount=3)
handler.setFormatter(SecureFormatter(_fmt))

logger = logging.getLogger("crypto_core")
# Always log INFO and above, but ensure ERROR/CRITICAL are never filtered
logger.setLevel(logging.INFO)
logger.addHandler(handler)
logger.propagate = False

# opcional: imprimir no stderr em modo debug OU sempre para erros
if os.getenv("CG_DEBUG") or True:  # Always show errors in console
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(SecureFormatter("%(levelname)s: %(funcName)s:%(lineno)d | %(message)s"))
    # Only show WARNING and above in console to avoid spam
    sh.setLevel(logging.WARNING)
    logger.addHandler(sh)

def get_logger():
    return logger

def warn_critical(message: str):
    """Registra uma mensagem de aviso crítico"""
    logger.critical(message)

def log_error(message: str, exc_info=None):
    """Log error with optional exception info"""
    if exc_info:
        logger.error(f"{message}", exc_info=exc_info)
    else:
        logger.error(message)

def log_exception(message: str, exception: Exception):
    """Log exception with full traceback"""
    logger.exception(f"{message}: {exception}")

# Log initial startup message
logger.info("=== CryptGuard iniciado ===")
