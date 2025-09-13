"""
Central logger for CryptGuard.

Goals:
- Rotate log file at LOG_PATH.
- Redact secrets (hex, base64, tokens, passwords).
- Remove full tracebacks/locals (keep type+message only).
- Optional PySide6 integration (qInstallMessageHandler).

Public API: `logger`, `LOG_PATH`
"""

from __future__ import annotations
# -*- coding: utf-8 -*-

import logging
import os
import sys
from logging import Logger
from logging.handlers import RotatingFileHandler

from .paths import LOG_PATH
from .redactlog import NoLocalsFilter, RedactingFormatter

_DEF_LEVEL = os.getenv("CRYPTGUARD_LOG_LEVEL", "INFO").upper()
_LEVEL = getattr(logging, _DEF_LEVEL, logging.INFO)


def _ensure_log_dir() -> None:
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(LOG_PATH.parent, 0o700)
    except Exception:
        # Avoid raising directory permission errors during logging setup
        pass


def _build_logger() -> Logger:
    _ensure_log_dir()
    lg = logging.getLogger("crypto_core")
    lg.setLevel(_LEVEL)
    lg.propagate = False

    # Avoid duplicate handlers on re-import
    if lg.handlers:
        return lg

    fh = RotatingFileHandler(
        LOG_PATH,
        maxBytes=5 * 1024 * 1024,  # 5 MiB
        backupCount=3,
        encoding="utf-8",
        delay=True,
    )
    fmt = RedactingFormatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S%z",
        enable_colors=False,
    )
    fh.setFormatter(fmt)
    lg.addHandler(fh)

    # Optional stderr handler when debugging
    if _LEVEL <= logging.DEBUG:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(
            RedactingFormatter(
                fmt="%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%H:%M:%S",
                enable_colors=True,
            )
        )
        lg.addHandler(sh)

    # Filter out locals/tracebacks
    lg.addFilter(NoLocalsFilter())

    # Optional Qt integration
    try:
        from PySide6.QtCore import qInstallMessageHandler, QtMsgType

        def _qt_handler(msg_type: int, context, message: str) -> None:  # type: ignore[override]
            if msg_type == QtMsgType.QtFatalMsg:
                lg.critical("QtFatal: %s", message)
            elif msg_type == QtMsgType.QtCriticalMsg:
                lg.error("QtCritical: %s", message)
            elif msg_type == QtMsgType.QtWarningMsg:
                lg.warning("QtWarning: %s", message)
            else:
                lg.info("QtInfo: %s", message)

        qInstallMessageHandler(_qt_handler)
    except Exception:
        # PySide6 not available
        pass

    lg.info("=== CryptGuard iniciado ===")
    return lg


logger: Logger = _build_logger()

# Retrocompatibilidade: antigos chamavam SecureFormatter a partir deste módulo
SecureFormatter = RedactingFormatter

# Re-export for convenience
__all__ = ["logger", "LOG_PATH", "SecureFormatter"]
