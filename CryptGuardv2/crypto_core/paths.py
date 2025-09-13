"""
Path constants for CryptGuard - separate from config to avoid circular imports.
"""
# -*- coding: utf-8 -*-

import os
from pathlib import Path

# Base directory for CryptGuard data
if os.name == "nt":  # Windows
    BASE_DIR = Path.home() / "AppData" / "Local" / "CryptGuard"
else:  # Unix-like
    BASE_DIR = Path.home() / ".cryptguard"

# Log file location
LOG_PATH = BASE_DIR / "cryptguard.log"

def ensure_base_dir() -> None:
    """Create the base directory with restricted permissions (best-effort)."""
    try:
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(BASE_DIR, 0o700)
    except Exception:
        # Do not raise logging-related directory errors
        pass
