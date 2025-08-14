"""
Path constants for CryptGuard - separate from config to avoid circular imports.
"""

import os
from pathlib import Path

# Base directory for CryptGuard data
if os.name == "nt":  # Windows
    BASE_DIR = Path.home() / "AppData" / "Local" / "CryptGuard"
else:  # Unix-like
    BASE_DIR = Path.home() / ".cryptguard"

# Log file location
LOG_PATH = BASE_DIR / "cryptguard.log"
