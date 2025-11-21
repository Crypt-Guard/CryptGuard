"""
CryptGuard platform helpers built on top of Python's stdlib ``platform``.

The package exposes convenience flags (``IS_WIN`` / ``IS_LINUX``) and
re-exports the stdlib API so existing imports such as ``from platform import
system`` keep working when swapped to ``cg_platform``.
"""

from __future__ import annotations

import platform as _STD_PLATFORM
import sys
from typing import Any

IS_WIN = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")

_STD_ALL = set(getattr(_STD_PLATFORM, "__all__", []))
__all__ = sorted(_STD_ALL | {"IS_WIN", "IS_LINUX", "fs_paths", "win_effects", "linux_env"})


def __getattr__(name: str) -> Any:
    """Delegate unknown attributes to the stdlib ``platform`` module."""
    return getattr(_STD_PLATFORM, name)


def __dir__() -> list[str]:
    items = set(globals()) | set(dir(_STD_PLATFORM))
    return sorted(items)


# Late imports to avoid circular dependencies.
from . import fs_paths  # noqa: E402,F401
from . import linux_env  # noqa: E402,F401
from . import win_effects  # noqa: E402,F401

