from __future__ import annotations
# -*- coding: utf-8 -*-

import logging
import re
from typing import Pattern


class NoLocalsFilter(logging.Filter):
    """
    Avoid logging full tracebacks with locals; keep only type+message.
    """

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: D401
        if record.exc_info:
            etype, evalue, _tb = record.exc_info
            try:
                record.msg = f"{record.msg} | {etype.__name__}: {evalue}"
            except Exception:
                pass
            record.exc_info = None
        return True


class RedactingFormatter(logging.Formatter):
    """
    Formatter that REDACTS sensitive content:
      - long hex (>=40 chars) → [hex_redacted]
      - common base64 (>=32 chars) → [b64_redacted]
      - suspicious key=value pairs (password|token|api_key|key|secret) → [redacted]
    """

    _HEX_RE: Pattern[str] = re.compile(r"\b[0-9a-fA-F]{40,}\b")
    _B64_RE: Pattern[str] = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")
    _KEYVAL_RE: Pattern[str] = re.compile(
        r"(?i)\b(password|passwd|pwd|secret|token|api[-_]?key|key)\s*[=:]\s*([^\s,;]+)"
    )

    def __init__(self, fmt: str, datefmt: str | None = None, enable_colors: bool = False):
        super().__init__(fmt=fmt, datefmt=datefmt)
        self._colors = enable_colors

    def _redact(self, msg: str) -> str:
        msg = self._HEX_RE.sub("[hex_redacted]", msg)
        msg = self._B64_RE.sub("[b64_redacted]", msg)
        msg = self._KEYVAL_RE.sub(lambda m: f"{m.group(1)}=[redacted]", msg)
        return msg

    def format(self, record: logging.LogRecord) -> str:
        try:
            raw = super().format(record)
        except Exception:
            raw = record.getMessage()
        out = self._redact(raw)
        if self._colors:
            try:
                if record.levelno >= logging.ERROR:
                    return f"\x1b[31m{out}\x1b[0m"
                elif record.levelno >= logging.WARNING:
                    return f"\x1b[33m{out}\x1b[0m"
                elif record.levelno >= logging.INFO:
                    return f"\x1b[37m{out}\x1b[0m"
                else:
                    return f"\x1b[90m{out}\x1b[0m"
            except Exception:
                pass
        return out
