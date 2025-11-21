"""
Filesystem location helpers backed by ``QStandardPaths``.

This keeps configuration/data/cache/log directories consistent across Windows
and Linux without hardcoded paths. Functions are cached so directories are
created only once per process.
"""

from __future__ import annotations

import contextlib
import functools
from pathlib import Path

from PySide6.QtCore import QStandardPaths

from . import IS_LINUX, IS_WIN

APP_NAME = "CryptGuardv2"
ORG_NAME = "CryptGuard"


def _append_app_name(path: Path) -> Path:
    """Ensure the returned path ends with ``ORG_NAME/APP_NAME``."""
    try:
        lower_name = path.name.lower()
        if lower_name == APP_NAME.lower():
            return path
        if lower_name == ORG_NAME.lower():
            return path / APP_NAME
    except Exception:
        return path / ORG_NAME / APP_NAME
    return path / ORG_NAME / APP_NAME


def _ensure_dir(location: str | None, fallback: Path) -> Path:
    candidate = Path(location) if location else fallback
    candidate = _append_app_name(candidate)
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate


@functools.lru_cache(maxsize=None)
def app_config_dir() -> Path:
    """Return the writable configuration directory."""
    fallback = Path.home() / ".config" if not IS_WIN else Path.home() / "AppData" / "Roaming"
    return _ensure_dir(
        QStandardPaths.writableLocation(QStandardPaths.AppConfigLocation),
        fallback,
    )


@functools.lru_cache(maxsize=None)
def app_data_dir() -> Path:
    """Return the writable application data directory."""
    if IS_WIN:
        fallback = Path.home() / "AppData" / "Local"
    else:
        fallback = Path.home() / ".local" / "share"
    return _ensure_dir(
        QStandardPaths.writableLocation(QStandardPaths.AppDataLocation),
        fallback,
    )


@functools.lru_cache(maxsize=None)
def app_cache_dir() -> Path:
    """Return the writable cache directory."""
    fallback = Path.home() / ".cache" if IS_LINUX else app_data_dir()
    return _ensure_dir(
        QStandardPaths.writableLocation(QStandardPaths.CacheLocation),
        fallback,
    )


@functools.lru_cache(maxsize=None)
def app_logs_dir() -> Path:
    """Directory used to store application logs."""
    base = app_data_dir()
    path = base / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


@functools.lru_cache(maxsize=None)
def log_file_path() -> Path:
    """Path to the rotating log file."""
    return app_logs_dir() / "cryptguard.log"


def ensure_all_dirs() -> None:
    """Create standard directories eagerly."""
    app_config_dir()
    data_dir = app_data_dir()
    cache_dir = app_cache_dir()
    logs_dir = app_logs_dir()

    # On Linux tighten permissions to keep secrets private.
    if IS_LINUX:
        for path in (data_dir, cache_dir, logs_dir):
            with contextlib.suppress(OSError):
                path.chmod(0o700)
