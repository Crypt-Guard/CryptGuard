"""
Path constants for CryptGuard - separate from config to avoid circular imports.
"""

from __future__ import annotations

import contextlib

from cg_platform import IS_LINUX
from cg_platform.fs_paths import app_data_dir, ensure_all_dirs, log_file_path

# Base directory for CryptGuard data (QStandardPaths-backed).
BASE_DIR = app_data_dir()

# Log file location
LOG_PATH = log_file_path()


def ensure_base_dir() -> None:
    """Create the base directory and tighten permissions where possible."""
    try:
        ensure_all_dirs()
        if IS_LINUX:
            with contextlib.suppress(OSError):
                BASE_DIR.chmod(0o700)
                LOG_PATH.parent.chmod(0o700)
                if LOG_PATH.exists():
                    LOG_PATH.chmod(0o600)
    except Exception:
        # Do not raise logging-related directory errors
        pass
