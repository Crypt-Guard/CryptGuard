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
import os
from typing import Any, Optional, Union
from venv import logger

from .config import SecurityProfile, LOG_PATH  # reexport
# Substituímos o uso indireto de .factories aqui por wrappers diretos do core cg2.
try:
    from .cg2_ops import encrypt_to_cg2, decrypt_from_cg2
except ImportError:  # fallback (caso precise manter compat em runtime parcial)
    from .factories import encrypt as encrypt_to_cg2, decrypt as decrypt_from_cg2  # type: ignore

__all__ = ["encrypt", "decrypt", "SecurityProfile", "LOG_PATH"]

# Mapeamento de códigos curtos -> nomes internos (fonte única em algorithms)
from .algorithms import SHORT_TO_HUMAN as ALG_MAP, normalize_algo

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

# NOVOS WRAPPERS (assinatura explícita esperada pelo smoketest)
def encrypt(in_path: str,
            password: Union[str, bytes],
            *, algo: str,
            out_path: Optional[str] = None) -> str:
    """
    Wrapper compatível: exige 'algo' como keyword, aceita 'out_path'.
    Gera .cg2 se out_path ausente.
    """
    algo = normalize_algo(algo)
    pwd = password.encode() if isinstance(password, str) else password
    dst = out_path or str(Path(in_path).with_suffix(".cg2"))
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    # Encaminha para implementação central
    encrypt_to_cg2(in_path, dst, pwd, alg=algo)
    return dst

def decrypt(cg2_path: str,
            password: Union[str, bytes],
            *, out_path: Optional[str] = None,
            verify_only: bool = False) -> Optional[str]:
    """
    Wrapper compatível: suporta verify_only sem exigir out_path.
    Retorna caminho de saída ou 'OK'/None em verify_only.
    """
    pwd = password.encode() if isinstance(password, str) else password
    dst = out_path or _guess_out_path(str(cg2_path))
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    if verify_only:
        # cg2_ops expects (in_path, out_path, password, ...)
        ok = decrypt_from_cg2(cg2_path, dst, pwd, verify_only=True)
        return "OK" if ok else None
    # Route to core impl with correct parameter order
    res = decrypt_from_cg2(cg2_path, dst, pwd, verify_only=False)
    return res or dst

# ----------------------------------------------------------------------------
# Override wrappers to route via factories (v5 router)
from .factories import encrypt as _encrypt_factory, decrypt as _decrypt_factory  # noqa: E402

def encrypt(in_path: str,
            password: Union[str, bytes],
            *, algo: str,
            out_path: Optional[str] = None) -> str:  # type: ignore[no-redef]
    pwd = password.encode() if isinstance(password, str) else password
    dst = out_path or str(Path(in_path).with_suffix(".cg2"))
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    return _encrypt_factory(in_path, pwd, algo=algo, out_path=dst)


def decrypt(cg2_path: str,
            password: Union[str, bytes],
            *, out_path: Optional[str] = None,
            verify_only: bool = False) -> Optional[str]:  # type: ignore[no-redef]
    pwd = password.encode() if isinstance(password, str) else password
    dst = out_path or _guess_out_path(str(cg2_path))
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    res = _decrypt_factory(cg2_path, pwd, out_path=dst, verify_only=verify_only)
    return None if verify_only else (res or dst)

try:
    from modules.keyguard.integrate import attach_keyguard_sidebar
    if os.environ.get("CG_ENABLE_TK_KEYGUARD") == "1":
        attach_keyguard_sidebar(None)  # tenta descobrir o root e o self.vault
except Exception as e:
    logger.warning("KeyGuard sidebar indisponível: %s", e)
