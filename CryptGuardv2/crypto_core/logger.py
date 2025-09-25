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

import contextlib
import inspect
import logging
import os
import sys
import traceback
from logging import Logger
from logging.handlers import RotatingFileHandler
from typing import Any

from .log_utils import log_best_effort
from .paths import LOG_PATH
from .redactlog import NoLocalsFilter, RedactingFormatter


class SecureRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler com permissões de arquivo seguras (POSIX)."""

    def _set_secure_mode(self, path: str) -> None:
        if os.name != "nt":
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)

    def _open(self):
        """Override para aplicar permissões seguras após criar arquivo."""
        stream = super()._open()
        self._set_secure_mode(self.baseFilename)
        return stream

    def doRollover(self) -> None:
        super().doRollover()
        if os.name == "nt":
            return
        self._set_secure_mode(self.baseFilename)
        for idx in range(1, self.backupCount + 1):
            candidate = self.rotation_filename(f"{self.baseFilename}.{idx}")
            if os.path.exists(candidate):
                self._set_secure_mode(candidate)


_DEF_LEVEL = os.getenv("CRYPTGUARD_LOG_LEVEL", "INFO").upper()
_LEVEL = getattr(logging, _DEF_LEVEL, logging.INFO)

_DEBUG_LOCALS_FLAG = str(os.getenv("CRYPTGUARD_DEBUG_LOCALS", "0")).lower() in {
    "1",
    "true",
    "yes",
    "on",
}
_SENSITIVE_KEYS = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "key",
    "passphrase",
    "credential",
    "auth",
}
_ALLOWED_LOCAL_KEYS = {
    "path",
    "filepath",
    "filename",
    "operation",
    "status",
    "code",
    "reason",
    "user",
    "attempt",
    "attempts",
    "profile",
    "mode",
    "resource",
}
_MAX_CONTEXT_VALUE_LEN = 120


def _should_include_locals(logger_obj: Logger) -> bool:
    """Return True when locals may be logged (DEBUG level + opt-in env var)."""
    return _DEBUG_LOCALS_FLAG and logger_obj.isEnabledFor(logging.DEBUG)


def _truncate_value(value: Any, limit: int = _MAX_CONTEXT_VALUE_LEN) -> str:
    """Safely render a value to a bounded ASCII representation."""
    try:
        rendered = repr(value)
    except Exception:
        rendered = f"<{type(value).__name__}>"
    if len(rendered) > limit:
        return rendered[:limit] + "..."
    return rendered


def _sanitize_mapping(
    mapping: dict[str, Any], *, allowed_keys: set[str] | None | None = None
) -> dict[str, str]:
    """Collapse a mapping into a log-safe dictionary."""
    safe: dict[str, str] = {}
    items = getattr(mapping, "items", None)
    if callable(items):
        iterator = items()
    else:
        try:
            iterator = dict(mapping).items()
        except Exception:
            iterator = []
    for raw_key, value in iterator:
        key = str(raw_key)
        lowered = key.lower()
        if lowered.startswith("_") or callable(value):
            continue
        if lowered in _SENSITIVE_KEYS:
            safe[key] = "[REDACTED]"
            continue
        if allowed_keys is not None and lowered not in allowed_keys:
            safe[key] = "[hidden]"
            continue
        safe[key] = _truncate_value(value)
    return safe


def _ensure_iterable_mapping(obj: Any) -> dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    try:
        return dict(obj)  # type: ignore[arg-type]
    except Exception:
        return {"value": obj}


def _ensure_log_dir() -> None:
    with contextlib.suppress(OSError):
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(LOG_PATH.parent, 0o700)
            if LOG_PATH.exists():
                os.chmod(LOG_PATH, 0o600)


def _build_logger() -> Logger:
    _ensure_log_dir()
    lg = logging.getLogger("crypto_core")
    lg.setLevel(_LEVEL)
    lg.propagate = False

    if lg.handlers:
        return lg

    fh = SecureRotatingFileHandler(
        LOG_PATH,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
        delay=True,
    )
    fmt = RedactingFormatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s (%(pathname)s:%(lineno)d in %(funcName)s)",
        datefmt="%Y-%m-%d %H:%M:%S%z",
        enable_colors=False,
    )
    fh.setFormatter(fmt)
    lg.addHandler(fh)

    if _LEVEL <= logging.DEBUG:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(
            RedactingFormatter(
                fmt="%(asctime)s [%(levelname)s] %(message)s (%(pathname)s:%(lineno)d)",
                datefmt="%H:%M:%S",
                enable_colors=True,
            )
        )
        lg.addHandler(sh)

    lg.addFilter(NoLocalsFilter())

    try:
        from PySide6.QtCore import QtMsgType, qInstallMessageHandler

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
    except Exception as exc:
        logger.warning("Qt message handler setup failed: %s", exc)

    lg.info("=== CryptGuard iniciado ===")
    return lg


class DetailedLogger:
    """
    Enhanced logger wrapper that provides detailed error context and stack traces.
    """

    def __init__(self, base_logger: Logger):
        self._logger = base_logger

    def __getattr__(self, name):
        """Delegate standard logging methods to the base logger"""
        return getattr(self._logger, name)

    def exception_with_context(
        self,
        msg: str,
        exc: Exception | None = None,
        extra_context: dict[str, Any] | None = None,
    ) -> None:
        """
        Log an exception with contextual data while respecting secrecy constraints.

        Args:
            msg: Base error message
            exc: Exception to log (uses current if None)
            extra_context: Additional context dictionary
        """
        frame = inspect.currentframe()
        caller_frame = frame.f_back if frame else None
        try:
            context_info = []

            if caller_frame:
                caller_info = inspect.getframeinfo(caller_frame)
                context_info.append(
                    f"Caller: {caller_info.filename}:{caller_info.lineno} in {caller_info.function}"
                )
                if _should_include_locals(self._logger):
                    safe_locals = _sanitize_mapping(
                        caller_frame.f_locals, allowed_keys=_ALLOWED_LOCAL_KEYS
                    )
                    if safe_locals:
                        context_info.append(f"Local variables: {safe_locals}")
                elif _DEBUG_LOCALS_FLAG:
                    context_info.append("Local variables: [suppressed]")

            if extra_context:
                ctx = _ensure_iterable_mapping(extra_context)
                safe_context = _sanitize_mapping(ctx, allowed_keys=_ALLOWED_LOCAL_KEYS)
                if safe_context:
                    context_info.append(f"Extra context: {safe_context}")

            full_msg = msg if not context_info else f"{msg} | Context: {' | '.join(context_info)}"

            if exc:
                self._logger.error(full_msg, exc_info=(type(exc), exc, exc.__traceback__))
            else:
                self._logger.exception(full_msg)

        except Exception as log_exc:
            self._logger.error(f"{msg} | Logging error: {log_exc}")
            if exc:
                self._logger.exception("Original exception:")
        finally:
            if caller_frame is not None:
                del caller_frame
            if frame is not None:
                del frame

    def error_with_stack(self, msg: str, stack_limit: int = 10) -> None:
        """
        Log an error with current stack trace.

        Args:
            msg: Error message
            stack_limit: Maximum number of stack frames to include
        """
        try:
            stack_trace = traceback.format_stack(limit=stack_limit)
            stack_info = "".join(stack_trace[-stack_limit:])  # Get last N frames
            full_msg = f"{msg} | Stack trace:\n{stack_info}"
            self._logger.error(full_msg)
        except Exception as log_exc:
            self._logger.error(f"{msg} | Stack trace failed: {log_exc}")

    def vault_error(
        self,
        operation: str,
        vault_type: str,
        error: Exception,
        context: dict[str, Any] | None = None,
    ) -> None:
        """
        Specialized logging for vault-related errors.

        Args:
            operation: Operation being performed (create, open, save, etc.)
            vault_type: Type of vault (KeyGuard, CryptGuard)
            error: The exception that occurred
            context: Additional context like file paths, passwords (redacted), etc.
        """
        try:
            error_type = type(error).__name__
            error_msg = str(error)

            # Build context information
            context_parts = [
                f"Operation: {operation}",
                f"Vault type: {vault_type}",
                f"Error type: {error_type}",
                f"Error message: {error_msg}",
            ]

            if context:
                # Redact sensitive information
                safe_context = {}
                for k, v in context.items():
                    if any(
                        sensitive in k.lower()
                        for sensitive in ["password", "key", "secret", "token"]
                    ):
                        safe_context[k] = "[REDACTED]"
                    else:
                        safe_context[k] = str(v)[:200] + "..." if len(str(v)) > 200 else str(v)
                context_parts.append(f"Context: {safe_context}")

            # Get stack trace for the error
            if hasattr(error, "__traceback__") and error.__traceback__:
                tb_lines = traceback.format_tb(error.__traceback__)
                context_parts.append(f"Stack trace:\n{''.join(tb_lines)}")

            full_message = f"Vault {operation} failed | " + " | ".join(context_parts)
            self._logger.error(full_message)

        except Exception as log_exc:
            # Fallback logging
            self._logger.error(f"Vault {operation} failed: {error} | Logging error: {log_exc}")


# Create the enhanced logger instance
_base_logger = _build_logger()
logger: DetailedLogger = DetailedLogger(_base_logger)

# Retrocompatibilidade: antigos chamavam SecureFormatter a partir deste módulo
SecureFormatter = RedactingFormatter

# Re-export for convenience
__all__ = ["logger", "LOG_PATH", "SecureFormatter", "log_best_effort"]
