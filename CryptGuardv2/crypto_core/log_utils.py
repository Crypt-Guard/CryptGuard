from __future__ import annotations

import logging


def log_best_effort(channel: str, exc: BaseException, *, message: str | None = None) -> None:
    """Log a maintenance failure without interrupting normal flow."""
    logger = logging.getLogger(channel)
    msg = message or "Best-effort failure"
    logger.debug("%s: %s", msg, exc, exc_info=True)
