from __future__ import annotations

import logging


class NoLocalsFilter(logging.Filter):
    """
    Prevent logging of exception tracebacks with locals; keeps only type+message.
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

