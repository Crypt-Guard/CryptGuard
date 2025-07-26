"""
Logger com SecureFormatter – remove bytes sensíveis (hex + Base64).
"""
import logging
import os
import re
import sys
import io
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
handler.setLevel(logging.DEBUG)          # grava tudo no arquivo
logger  = logging.getLogger("crypto_core")
logger.setLevel(logging.DEBUG)           # mantém DEBUG→INFO→…
logger.addHandler(handler)
logger.propagate = False

# gravar warnings do módulo warnings no mesmo arquivo
logging.captureWarnings(True)

def _safe_console_stream() -> io.TextIOBase:
    """
    Retorna um stream de texto UTF‑8 seguro para o console.
    • Em runtime normal → sys.stderr (enc UTF‑8 wrapper).
    • Em PyInstaller (stderr == None) → descarta para NUL sem quebrar.
    """
    target = sys.stderr

    # Fallback quando rodando como executável PyInstaller
    if target is None:
        # cria um arquivo em NUL (Windows) ou /dev/null (POSIX)
        nul = "NUL" if os.name == "nt" else "/dev/null"
        target = open(nul, "w", buffering=1, encoding="utf‑8")

    # Se ainda assim não tiver .buffer, já é TextIO – podemos usar direto
    if not hasattr(target, "buffer"):
        return target  # type: ignore[return-value]

    # Caso normal: embrulhar buffer binário em TextIO UTF‑8
    return io.TextIOWrapper(
        target.buffer,
        encoding="utf‑8",
        errors="replace",
        line_buffering=True,
    )

# ─── console handler ────────────────────────────────────────────────────────
if os.getenv("CG_DEBUG", "1") == "1":
    console_handler = logging.StreamHandler(stream=_safe_console_stream())
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(SecureFormatter("%(levelname)s: %(funcName)s:%(lineno)d | %(message)s"))
    logger.addHandler(console_handler)

# ─── capturar exceções não tratadas ────────────────────────────────────────
def _ex_hook(exc_type, exc_value, exc_tb):
    # Registra traceback completo
    logger.exception("Uncaught exception", exc_info=(exc_type, exc_value, exc_tb))
    # Chama hook padrão (imprime no stderr)
    if _orig_ex_hook:
        _orig_ex_hook(exc_type, exc_value, exc_tb)

_orig_ex_hook = sys.excepthook
sys.excepthook = _ex_hook

# Python ≥3.8 – exceções em threads
if hasattr(logging, "excepthook"):
    import threading
    def _thread_ex_hook(args):
        logger.exception("Uncaught thread exception", exc_info=(args.exc_type,
                                                                args.exc_value,
                                                                args.exc_traceback))
        if _orig_thread_hook:
            _orig_thread_hook(args)
    _orig_thread_hook = threading.excepthook
    threading.excepthook = _thread_ex_hook

try:
    from PySide6.QtCore import qInstallMessageHandler, QtMsgType
    def _qt_handler(mode, context, message):
        if mode == QtMsgType.QtCriticalMsg:
            logger.error("QtCritical: %s", message)
        elif mode == QtMsgType.QtWarningMsg:
            logger.warning("QtWarning: %s", message)
        else:
            logger.info("QtInfo: %s", message)
    qInstallMessageHandler(_qt_handler)
except ImportError:
    pass  # PySide6 não disponível/necessário

# Log initial startup message
logger.info("=== CryptGuard iniciado ===")
# Log initial startup message
logger.info("=== CryptGuard iniciado ===")
