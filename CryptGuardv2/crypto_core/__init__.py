# -*- coding: utf-8 -*-
"""crypto_core — API pública canônica.

Exporta:
- encrypt/decrypt (de crypto_core.factories)
- SecurityProfile e LOG_PATH

Compat de kwargs:
- alg -> algo
- output -> out_path
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import SecurityProfile, LOG_PATH  # reexport
from .factories import encrypt as _enc, decrypt as _dec  # faces públicas

__all__ = ["encrypt", "decrypt", "SecurityProfile", "LOG_PATH"]

def _compat_kwargs(kwargs: dict) -> dict:
    if "algo" not in kwargs and "alg" in kwargs:
        kwargs["algo"] = kwargs.pop("alg")
    if "out_path" not in kwargs and "output" in kwargs:
        kwargs["out_path"] = kwargs.pop("output")
    return kwargs

def _guess_out_path(in_path: str) -> str:
    p = Path(in_path)
    # tentar leitura de header para detectar zip
    try:
        from .fileformat import read_header
        hdr = read_header(p)
        blob = ""
        if isinstance(hdr, (tuple, list)):
            blob = " ".join(str(x) for x in hdr)
        else:
            blob = str(hdr)
        if "zip" in blob.lower():
            return str(p.with_suffix(".zip"))
    except Exception:
        pass
    # fallback seguro
    return str(p.with_suffix("")) if p.suffix.lower() == ".cg2" else str(p)

def encrypt(*args, **kwargs):
    return _enc(*args, **_compat_kwargs(kwargs))

def decrypt(*args, **kwargs):
    kw = _compat_kwargs(kwargs)
    # Se verify_only=False e out_path ausente, decidir automaticamente
    if not kw.get("verify_only", False) and "out_path" not in kw:
        in_path = None
        if args:
            in_path = args[0]
        else:
            for k in ("in_path", "path", "input"):
                if k in kw:
                    in_path = kw[k]
                    break
        if in_path:
            kw["out_path"] = _guess_out_path(str(in_path))
    return _dec(*args, **kw)
