from __future__ import annotations

import string
import tkinter as tk
from tkinter import ttk

try:
    import ttkbootstrap as tb  # optional (for dark themes like 'superhero')

    TTK = tb
except Exception:  # fallback to std ttk
    tb = None
    TTK = ttk  # type: ignore

from crypto_core.log_utils import log_best_effort

from .password_generator import CHARSETS, MIN_TOTAL_BITS, OPT_TO_KEY, PasswordGenerator

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tk/ttk sidebar widget that implements the KeyGuard password generator UI.
Designed to be embedded to the right side of the CryptGuard main window.
"""


class KeyGuardPane(TTK.Frame):
    """
    Sidebar pane with:
      - length spinbox
      - charset radio buttons
      - checkbox 'Salvar no vault' and 'Aplicação' entry
      - readonly password entry with 'eye' toggle
      - entropy progress bar + label
      - action buttons (Gerar, Copiar, Limpar, Vault)
    The pane is self-contained and only needs a `vault` object with
    add_entry(name, password) and update_entry(name, password=...) methods.
    """

    def __init__(self, parent, vault=None, width=340, **kwargs):
        super().__init__(parent, **kwargs)

        self._vault = vault
        self._clipboard_timeout_ms = 15_000

        # Visual bounds / layout
        self.configure(width=width)
        self.grid_propagate(False)

        # ---------- Section: Parameters ----------
        lf = TTK.LabelFrame(self, text="KeyGuard — Gerador")
        lf.grid(row=0, column=0, sticky="nwe", padx=8, pady=(8, 4))
        lf.columnconfigure(1, weight=1)

        # Length
        TTK.Label(lf, text="Comprimento:").grid(row=0, column=0, sticky="e", padx=6, pady=4)
        self._length = tk.StringVar(value="16")
        self._spin = TTK.Spinbox(lf, from_=4, to=128, textvariable=self._length, width=6)
        self._spin.grid(row=0, column=1, sticky="w", padx=(2, 8), pady=4)

        # Charset options
        self._opt = tk.IntVar(value=4)
        labels = ("Números", "Letras", "Letras+Números", "Todos")
        for i, txt in enumerate(labels, start=1):
            rb = TTK.Radiobutton(lf, text=txt, value=i, variable=self._opt)
            rb.grid(row=i, column=0 if i % 2 else 1, sticky="w", padx=6, pady=2)

        # Save-to-vault toggle + application name
        self._save = tk.BooleanVar(value=False)
        TTK.Checkbutton(lf, text="Salvar no vault", variable=self._save).grid(
            row=5, column=0, columnspan=2, sticky="w", padx=6, pady=(6, 2)
        )
        TTK.Label(lf, text="Aplicação:").grid(row=6, column=0, sticky="e", padx=6, pady=2)
        self._app = TTK.Entry(lf, width=24)
        self._app.grid(row=6, column=1, sticky="we", padx=(2, 8), pady=2)

        # ---------- Section: Output (password) ----------
        out = TTK.Frame(self)
        out.grid(row=1, column=0, sticky="nwe", padx=8, pady=(4, 6))
        out.columnconfigure(0, weight=1)

        self._pwd_var = tk.StringVar()
        self._pwd_entry = TTK.Entry(
            out,
            textvariable=self._pwd_var,
            font=("Consolas", 12),
            state="readonly",
            show="•",
        )
        self._pwd_entry.grid(row=0, column=0, sticky="we", ipadx=6, ipady=4)

        self._eye = TTK.Checkbutton(out, text="👁", command=self._toggle_eye, style="Toolbutton")
        self._eye.grid(row=0, column=1, padx=4)

        self._bar = TTK.Progressbar(out, maximum=120, length=280)
        self._bar.grid(row=1, column=0, columnspan=2, pady=6, sticky="we")

        self._lbl = TTK.Label(out, text="Entropia / força")
        self._lbl.grid(row=2, column=0, columnspan=2)

        # ---------- Section: Buttons ----------
        btns = TTK.Frame(self)
        btns.grid(row=2, column=0, pady=(6, 8))

        self._gen_btn = TTK.Button(btns, text="Gerar", command=self._on_generate)
        self._cpy_btn = TTK.Button(btns, text="Copiar", command=self._on_copy)
        self._clr_btn = TTK.Button(btns, text="Limpar", command=self._on_clear)
        self._vault_btn = TTK.Button(btns, text="Vault", command=self._open_vault)

        self._gen_btn.pack(side="left", padx=6)
        self._cpy_btn.pack(side="left", padx=6)
        self._clr_btn.pack(side="left", padx=6)
        self._vault_btn.pack(side="left", padx=6)

        # Keyboard shortcuts
        self.bind_all("<Control-g>", lambda *_: self._on_generate())
        self.bind_all("<Control-c>", lambda *_: self._on_copy())
        self.bind_all("<Control-l>", lambda *_: self._on_clear())
        self.bind_all("<Escape>", lambda *_: self._maybe_close())

        # Logic core
        self._gen = PasswordGenerator()

    # ----- UI helpers ---------------------------------------------------------
    def _toggle_eye(self):
        if self._pwd_entry.cget("show") == "•":
            self._pwd_entry.config(show="")
        else:
            self._pwd_entry.config(show="•")

    def _read_length(self) -> int:
        try:
            n = int(self._length.get())
        except Exception:
            n = 16
        n = max(4, min(128, n))
        self._length.set(str(n))
        return n

    def _current_charset(self) -> str:
        key = OPT_TO_KEY.get(self._opt.get(), "full")
        return CHARSETS[key]

    def _on_generate(self, *_):
        length = self._read_length()
        charset = self._current_charset()
        pwd = self._gen.generate(length, charset)

        bits = PasswordGenerator.calculate_entropy(pwd, charset)
        self._pwd_var.set(pwd)
        self._bar["value"] = min(bits, 120.0)

        msg = f"Entropia: {bits:.1f} bits"
        classes = {
            "lower": any(c in string.ascii_lowercase for c in pwd),
            "upper": any(c in string.ascii_uppercase for c in pwd),
            "digit": any(c in string.digits for c in pwd),
            "symbol": any(c in string.punctuation for c in pwd),
        }
        MIN_CLASS_TYPES = 2
        if bits < MIN_TOTAL_BITS or sum(classes.values()) < MIN_CLASS_TYPES:
            msg += " ⚠️"
        self._lbl.config(text=msg)

        if self._save.get() and self._vault is not None:
            name = (self._app.get() or "Sem_nome").strip()
            try:
                self._vault.add_entry(name, pwd)
            except Exception:
                try:
                    self._vault.update_entry(name, password=pwd)  # type: ignore
                except Exception as exc:
                    log_best_effort(__name__, exc)

    def _on_copy(self, *_):
        s = self._pwd_var.get()
        if not s:
            return
        try:
            self.clipboard_clear()
        except Exception as exc:
            log_best_effort(__name__, exc)
        self.clipboard_append(s)
        self.after(self._clipboard_timeout_ms, self._safe_clip_clear)

    def _safe_clip_clear(self):
        try:
            self.clipboard_clear()
        except Exception as exc:
            log_best_effort(__name__, exc)

    def _on_clear(self, *_):
        self._safe_clip_clear()
        self._pwd_var.set("")
        self._bar["value"] = 0
        self._lbl.config(text="Entropia / força")
        if self._pwd_entry.cget("show") == "":
            self._pwd_entry.config(show="•")

    def _open_vault(self):
        # best-effort hook; real app should wire to existing Vault dialog
        try:
            if hasattr(self._vault, "open_ui"):
                self._vault.open_ui()
        except Exception as exc:
            log_best_effort(__name__, exc)

    def _maybe_close(self):
        # this is a sidebar; ESC shouldn't destroy parent window
        pass


def create_sidebar(parent, vault=None, width=340):
    pane = KeyGuardPane(parent, vault=vault, width=width)
    return pane
