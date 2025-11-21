"""
Windows-specific window effects (dark title bar, Mica/Backdrop).

Calls are guarded so importing the module on non-Windows platforms is safe.
"""

from __future__ import annotations

import sys

if sys.platform.startswith("win"):
    import ctypes
    import ctypes.wintypes as wt

    DWMWA_USE_IMMERSIVE_DARK_MODE = 20
    DWMWA_SYSTEMBACKDROP_TYPE = 38
    DWMSBT_MAINWINDOW = 2

    def try_enable_dark_titlebar(hwnd: int) -> None:
        try:
            value = wt.BOOL(True)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                wt.HWND(hwnd),
                DWMWA_USE_IMMERSIVE_DARK_MODE,
                ctypes.byref(value),
                ctypes.sizeof(value),
            )
        except Exception:
            pass

    def try_enable_mica(hwnd: int) -> None:
        try:
            backdrop = wt.INT(DWMSBT_MAINWINDOW)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                wt.HWND(hwnd),
                DWMWA_SYSTEMBACKDROP_TYPE,
                ctypes.byref(backdrop),
                ctypes.sizeof(backdrop),
            )
        except Exception:
            pass
else:

    def try_enable_dark_titlebar(hwnd: int) -> None:
        return None

    def try_enable_mica(hwnd: int) -> None:
        return None

