"""
Cross-platform bootstrap helpers for CryptGuardv2.

This module adjusts Qt environment settings before QApplication is created so
the application can run on both Windows and Linux (Wayland/X11) without extra
native dependencies.
"""

from __future__ import annotations

import os
import sys

IS_WIN = sys.platform.startswith("win")
IS_LINUX = sys.platform.startswith("linux")

# 1) Linux: prefer Wayland, fallback to X11/xcb if Wayland is unavailable.
if IS_LINUX and "QT_QPA_PLATFORM" not in os.environ:
    session = os.environ.get("XDG_SESSION_TYPE", "").lower()
    if session == "wayland" or os.environ.get("WAYLAND_DISPLAY"):
        os.environ["QT_QPA_PLATFORM"] = "wayland;xcb"
    else:
        os.environ["QT_QPA_PLATFORM"] = "xcb"

# 2) Leave style selection to Qt; do not force legacy themes.
# 3) Do not hardcode plugin paths here—PyInstaller hooks will handle it.
