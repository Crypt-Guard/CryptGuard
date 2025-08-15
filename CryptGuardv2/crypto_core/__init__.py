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
from typing import Any, Optional, Union

from .config import SecurityProfile, LOG_PATH  # reexport
# Substituímos o uso indireto de .factories aqui por wrappers diretos do core cg2.
try:
    from .cg2_ops import encrypt_to_cg2, decrypt_from_cg2
except ImportError:  # fallback (caso precise manter compat em runtime parcial)
    from .factories import encrypt as encrypt_to_cg2, decrypt as decrypt_from_cg2  # type: ignore

__all__ = ["encrypt", "decrypt", "SecurityProfile", "LOG_PATH"]

# Mapeamento de códigos curtos -> nomes internos
ALG_MAP = {
    "AESG": "AES-256-GCM",
    "ACTR": "AES-256-CTR",
    "XC20": "XChaCha20-Poly1305",
    "CH20": "ChaCha20-Poly1305",
}

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
    algo = ALG_MAP.get(algo, algo)
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
    if verify_only:
        ok = decrypt_from_cg2(cg2_path, pwd, verify_only=True)
        return "OK" if ok else None
    dst = out_path or _guess_out_path(str(cg2_path))
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    res = decrypt_from_cg2(cg2_path, pwd, out_path=dst)
    return res or dst
