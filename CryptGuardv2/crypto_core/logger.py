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
import traceback
import inspect
from typing import Any, Dict, Optional
from logging import Logger
from logging.handlers import RotatingFileHandler

from .paths import LOG_PATH
from .redactlog import NoLocalsFilter, RedactingFormatter


class SecureRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler com permissões de arquivo seguras (POSIX)"""
    
    def _open(self):
        """Override para aplicar permissões seguras após criar arquivo"""
        stream = super()._open()
        # P1.3: Aplicar permissões restritivas logo após criar o arquivo
        if os.name != "nt":
            try:
                os.chmod(self.baseFilename, 0o600)
            except Exception:
                # best-effort, não deve quebrar o logging
                pass
        return stream

_DEF_LEVEL = os.getenv("CRYPTGUARD_LOG_LEVEL", "INFO").upper()
_LEVEL = getattr(logging, _DEF_LEVEL, logging.INFO)


def _ensure_log_dir() -> None:
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(LOG_PATH.parent, 0o700)
            # P1.3: Garantir permissões restritivas no arquivo de log também
            if LOG_PATH.exists():
                os.chmod(LOG_PATH, 0o600)
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

    fh = SecureRotatingFileHandler(
        LOG_PATH,
        maxBytes=5 * 1024 * 1024,  # 5 MiB
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

    # Optional stderr handler when debugging
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


class DetailedLogger:
    """
    Enhanced logger wrapper that provides detailed error context and stack traces.
    """
    
    def __init__(self, base_logger: Logger):
        self._logger = base_logger
    
    def __getattr__(self, name):
        """Delegate standard logging methods to the base logger"""
        return getattr(self._logger, name)
    
    def exception_with_context(self, msg: str, exc: Optional[Exception] = None, 
                             extra_context: Optional[Dict[str, Any]] = None) -> None:
        """
        Log an exception with detailed context information.
        
        Args:
            msg: Base error message
            exc: Exception to log (uses current if None)
            extra_context: Additional context dictionary
        """
        try:
            # Get current frame info
            frame = inspect.currentframe()
            caller_frame = frame.f_back if frame else None
            
            context_info = []
            
            # Add caller information
            if caller_frame:
                caller_info = inspect.getframeinfo(caller_frame)
                context_info.append(f"Caller: {caller_info.filename}:{caller_info.lineno} in {caller_info.function}")
                
                # Add local variables (safely)
                try:
                    local_vars = {k: str(v)[:100] + "..." if len(str(v)) > 100 else str(v) 
                                for k, v in caller_frame.f_locals.items() 
                                if not k.startswith('_') and not callable(v)}
                    if local_vars:
                        context_info.append(f"Local variables: {local_vars}")
                except Exception:
                    context_info.append("Local variables: <failed to capture>")
            
            # Add extra context
            if extra_context:
                context_info.append(f"Extra context: {extra_context}")
            
            # Format the full message
            full_msg = f"{msg}"
            if context_info:
                full_msg += f" | Context: {' | '.join(context_info)}"
            
            # Log with exception info
            if exc:
                self._logger.error(full_msg, exc_info=(type(exc), exc, exc.__traceback__))
            else:
                self._logger.exception(full_msg)
                
        except Exception as log_exc:
            # Fallback if detailed logging fails
            self._logger.error(f"{msg} | Logging error: {log_exc}")
            if exc:
                self._logger.exception("Original exception:")
    
    def error_with_stack(self, msg: str, stack_limit: int = 10) -> None:
        """
        Log an error with current stack trace.
        
        Args:
            msg: Error message
            stack_limit: Maximum number of stack frames to include
        """
        try:
            stack_trace = traceback.format_stack(limit=stack_limit)
            stack_info = ''.join(stack_trace[-stack_limit:])  # Get last N frames
            full_msg = f"{msg} | Stack trace:\n{stack_info}"
            self._logger.error(full_msg)
        except Exception as log_exc:
            self._logger.error(f"{msg} | Stack trace failed: {log_exc}")
    
    def vault_error(self, operation: str, vault_type: str, error: Exception, 
                   context: Optional[Dict[str, Any]] = None) -> None:
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
                f"Error message: {error_msg}"
            ]
            
            if context:
                # Redact sensitive information
                safe_context = {}
                for k, v in context.items():
                    if any(sensitive in k.lower() for sensitive in ['password', 'key', 'secret', 'token']):
                        safe_context[k] = "[REDACTED]"
                    else:
                        safe_context[k] = str(v)[:200] + "..." if len(str(v)) > 200 else str(v)
                context_parts.append(f"Context: {safe_context}")
            
            # Get stack trace for the error
            if hasattr(error, '__traceback__') and error.__traceback__:
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
__all__ = ["logger", "LOG_PATH", "SecureFormatter"]
