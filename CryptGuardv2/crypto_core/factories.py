# ============================================================================
# === Canonical API (v2.1.5c) — single public face ==========================
from __future__ import annotations

from pathlib import Path as _Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import SecurityProfile  # noqa: F401


_LOGICAL_TO_HUMAN = {
    "AESG": "AES-256-GCM",
    "ACTR": "AES-256-CTR",
    "XC20": "XChaCha20-Poly1305",
    "CH20": "ChaCha20-Poly1305",
}

def _normalize_algo(a: str) -> str:
    up = (a or "").strip().upper()
    if up in _LOGICAL_TO_HUMAN:
        return _LOGICAL_TO_HUMAN[up]
    if a in _LOGICAL_TO_HUMAN.values():
        return a
    raise ValueError(f"Algoritmo não suportado: {a!r}. Use AESG|ACTR|XC20|CH20.")

def encrypt(
    in_path: str | _Path,
    password: str | bytes,
    *,
    algo: str,
    out_path: str | _Path,
    profile: "SecurityProfile" | None = None,  # noqa: UP037
    expires_at: int | None = None,
    progress_cb=None,
    pad_block: int = 0,
) -> str:
    from .cg2_ops import encrypt_to_cg2 as _enc_cg2
    if isinstance(password, str):
        password = password.encode()
    src = _Path(in_path)
    dst = _Path(out_path)
    if dst.suffix.lower() != ".cg2":
        dst = dst.with_suffix(".cg2")
    if profile is None:
        from .config import SecurityProfile
        profile = SecurityProfile.BALANCED
    human = _normalize_algo(algo)
    res = _enc_cg2(src, dst, password, human, profile, expires_at, progress_cb=progress_cb, pad_block=pad_block)
    return str(_Path(res).resolve())

def decrypt(
    in_path: str | _Path,
    password: str | bytes,
    *,
    out_path: str | _Path,
    verify_only: bool = False,
    progress_cb=None,
) -> str | None:
    from .cg2_ops import decrypt_from_cg2 as _dec_cg2
    src = _Path(in_path)
    dst = _Path(out_path)
    if isinstance(password, str):
        password = password.encode()
    res = _dec_cg2(src, dst, password, verify_only=verify_only, progress_cb=progress_cb)
    if verify_only:
        return None
    return str(_Path(res).resolve())

def Encrypt(*args, **kwargs):
    if "algo" not in kwargs and "alg" in kwargs:
        kwargs["algo"] = kwargs.pop("alg")
    if "out_path" not in kwargs and "output" in kwargs:
        kwargs["out_path"] = kwargs.pop("output")
    return encrypt(*args, **kwargs)

def Decrypt(*args, **kwargs):
    if "out_path" not in kwargs and "output" in kwargs:
        kwargs["out_path"] = kwargs.pop("output")
    return decrypt(*args, **kwargs)
# ===========================================================================
