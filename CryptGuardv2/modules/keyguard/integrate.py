#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Non-invasive integration helper for embedding the KeyGuardPane
on the right side of the main CryptGuard window.

Usage (inside your main window class after building the main layout):

    from modules.keyguard.integrate import attach_keyguard_sidebar
    attach_keyguard_sidebar(self)
"""
from __future__ import annotations

import tkinter as tk
from typing import Optional

try:
    import ttkbootstrap as tb  # type: ignore
    TTK = tb
except Exception:
    from tkinter import ttk as TTK  # type: ignore

from .keyguard_widget import KeyGuardPane


def _resolve_root(app) -> tk.Misc:
    # heuristics to get a Tk root/container from different app styles
    if isinstance(app, tk.Tk) or isinstance(app, tk.Toplevel) or isinstance(app, tk.Frame):
        return app
    for attr in ("root", "master", "frame", "container", "main"):
        if hasattr(app, attr):
            obj = getattr(app, attr)
            if isinstance(obj, (tk.Tk, tk.Toplevel, tk.Frame)):
                return obj
    # fallback
    return app


def _find_right_container(root: tk.Misc) -> tk.Misc:
    """
    Try to locate a right-side container; otherwise just create one.
    The container uses pack(side=RIGHT, fill=Y) so it doesn't disturb
    the main left panel (CryptGuard file crypto UI).
    """
    container = None
    # search by conventional names if developer already created a pane
    for name in ("right_pane", "sidebar", "keyguard_pane"):
        if hasattr(root, name):
            container = getattr(root, name)
            break
    if container is None:
        container = TTK.Frame(root, name="keyguard_sidebar")
        container.pack(side="right", fill="y")
    return container


def attach_keyguard_sidebar(app, vault: Optional[object] = None, width: int = 340):
    """
    Create and attach the KeyGuard sidebar to the main window.
    - `app`: the main application instance (or a Tk container)
    - `vault`: optional vault interface; if None, the 'Salvar no vault' checkbox still shows,
               but saving will be disabled silently.
    - `width`: sidebar width in pixels.
    """
    root = _resolve_root(app)
    container = _find_right_container(root)

    # If caller didn't pass a vault adapter, try to discover a likely one
    if vault is None:
        for attr in ("vault", "Vault", "vault_mgr", "vault_manager"):
            if hasattr(app, attr):
                vault = getattr(app, attr)
                break

    pane = KeyGuardPane(container, vault=vault, width=width)
    pane.pack(side="top", fill="x", expand=False, padx=4, pady=4)

    # Optionally expose a reference on the app to allow later interactions
    try:
        setattr(app, "keyguard_pane", pane)
    except Exception:
        pass

    return pane

