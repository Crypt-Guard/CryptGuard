"""
KeyGuard sidebar module for CryptGuard.

This package provides:
- password_generator: core generator and entropy calculation
- keyguard_widget: Tk/ttk widget (legacy)
- integrate: Tk helper to attach in Tk apps
- qt_pane: PySide6 (Qt Widgets) sidebar and attach helper
"""

from .password_generator import PasswordGenerator, CHARSETS, OPT_TO_KEY, MIN_TOTAL_BITS

# Tk variant (optional)
try:
    from .keyguard_widget import KeyGuardPane            # noqa: F401
    from .integrate import attach_keyguard_sidebar       # noqa: F401
except Exception:  # not required for Qt builds
    KeyGuardPane = None                                  # type: ignore
    attach_keyguard_sidebar = None                       # type: ignore

# Qt variant
from .qt_pane import KeyGuardPaneQt, attach_keyguard_qt
from .vault_backend import VaultManager, VaultEntry
from .vault_qt import KeyGuardVaultDialog

__all__ = [
    "PasswordGenerator", "CHARSETS", "OPT_TO_KEY", "MIN_TOTAL_BITS",
    "KeyGuardPane", "attach_keyguard_sidebar", "KeyGuardPaneQt", "attach_keyguard_qt",
    "VaultManager", "VaultEntry", "KeyGuardVaultDialog"
]
