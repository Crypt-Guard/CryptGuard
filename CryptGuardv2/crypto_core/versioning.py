from __future__ import annotations

import os

DEFAULT_MIN_SUPPORTED_VERSION = 5
MIN_SUPPORTED_VERSION = int(os.getenv("CG_MIN_SUPPORTED_VERSION", str(DEFAULT_MIN_SUPPORTED_VERSION)))


class UnsupportedFormatVersionError(Exception):
    """Raised when attempting to open a format older than the minimum supported version."""


__all__ = [
    "DEFAULT_MIN_SUPPORTED_VERSION",
    "MIN_SUPPORTED_VERSION",
    "UnsupportedFormatVersionError",
]
