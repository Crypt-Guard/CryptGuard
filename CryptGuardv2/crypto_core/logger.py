"""
Logger com SecureFormatter – remove bytes sensíveis (hex / Base64) e centraliza configuração.
"""

from __future__ import annotations

import logging
import re
import sys
from logging import Logger
from logging.handlers import RotatingFileHandler

from .paths import LOG_PATH  # fonte única de verdade para o caminho do log


class SecureFormatter(logging.Formatter):
    """
    Sanitiza mensagens para evitar vazamento de segredos (chaves, senhas, blobs).
    - Mascara sequências hexadecimais longas (>= 32 chars).
    - Mascara sequências base64 longas (>= 40 chars).
    - Mascara padrões comuns 'password=...', 'secret=...', 'key=...'.
    """

    HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
    B64_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
    KV_RE = re.compile(r"(?i)(password|secret|key)\s*=\s*([^\s,;]+)")

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)

        # hex
        msg = self.HEX_RE.sub(lambda m: f"<hex:{len(m.group(0))}B REDACTED>", msg)
        # base64
        msg = self.B64_RE.sub(lambda m: f"<b64:{len(m.group(0))}B REDACTED>", msg)
        # key=value patterns
        msg = self.KV_RE.sub(lambda m: f"{m.group(1)}=<REDACTED>", msg)
        return msg


def _build_handler() -> logging.Handler:
    """
    Tenta criar um RotatingFileHandler; se falhar, faz fallback para stderr.
    """
    fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    try:
        # Garante diretório
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            LOG_PATH,
            maxBytes=1_000_000,
            backupCount=5,
            encoding="utf-8",
            delay=True,
        )
    except Exception:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(SecureFormatter(fmt=fmt, datefmt=datefmt))
    return handler


# ③ configuração de logger
logger: Logger = logging.getLogger("crypto_core")
logger.setLevel(logging.DEBUG)  # controle global; ajuste no app conforme necessário
# Evita handlers duplicados em reimport
if not logger.handlers:
    handler = _build_handler()
    logger.addHandler(handler)
logger.propagate = False  # não propagar para root (evita logs em dobro)


# Integração opcional com Qt (se PySide6 estiver disponível)
try:
    from PySide6.QtCore import QtMsgType, qInstallMessageHandler

    def _qt_handler(mode, context, message):
        if mode == QtMsgType.QtCriticalMsg:
            logger.error("QtCritical: %s", message)
        elif mode == QtMsgType.QtWarningMsg:
            logger.warning("QtWarning: %s", message)
        else:
            logger.info("QtInfo: %s", message)

    qInstallMessageHandler(_qt_handler)
except Exception:
    # PySide6 não disponível/necessário
    pass

# Mensagem única de inicialização
logger.info("=== CryptGuard iniciado ===")

# Re-export para conveniência (outros módulos fazem `from .logger import LOG_PATH`)
__all__ = ["logger", "LOG_PATH"]
