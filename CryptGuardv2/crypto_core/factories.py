# ============================================================================
# === Canonical API (v2.1.5c) — single public face ==========================
from __future__ import annotations

from pathlib import Path as _Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import SecurityProfile  # noqa: F401


# Algorithm normalization kept for backward compatibility (unused in v5)

# New v5 routing utilities
from .fileformat_v5 import read_header_version_any as _read_ver_any

def encrypt(
    in_path: str | _Path,
    password: str | bytes,
    *,
    algo: str,  # ignored in v5 (kept for compatibility)
    out_path: str | _Path,
    profile: "SecurityProfile" | None = None,  # noqa: UP037
    expires_at: int | None = None,
    progress_cb=None,
    pad_block: int = 0,
    kdf_profile: str | None = None,
    padding: str | None = None,
    keyfile: str | _Path | None = None,
    hide_filename: bool = False,
) -> str:
    # Force v5 encryption via SecretStream (PyNaCl required)
    # UI-supplied 'algo' is ignored; always XChaCha20-Poly1305 SecretStream.
    from .xchacha_stream import XChaChaStream

    if isinstance(password, str):
        password = password.encode()
    src = _Path(in_path)
    dst = _Path(out_path)
    if dst.suffix.lower() != ".cg2":
        dst = dst.with_suffix(".cg2")

    # Resolve padding policy preference
    pad_policy = None
    if isinstance(padding, str):
        p = padding.strip().lower()
        if p in ("off", "4k", "16k"):
            pad_policy = p
    if pad_policy is None:
        # Map pad_block to the new padding policy: off/4k/16k
        if pad_block in (4096, 4 * 1024):
            pad_policy = "4k"
        elif pad_block in (16384, 16 * 1024):
            pad_policy = "16k"
        else:
            pad_policy = "off"

    # Resolve KDF profile
    kprof = (kdf_profile or "INTERACTIVE").upper()
    if kprof not in ("INTERACTIVE", "SENSITIVE"):
        kprof = "INTERACTIVE"

    res = XChaChaStream().encrypt_file(
        src,
        password,
        out_path=str(dst),
        kdf_profile=kprof,
        padding=pad_policy,
        keyfile=str(keyfile) if keyfile else None,
        hide_filename=bool(hide_filename),
    )
    return str(_Path(res).resolve())

def decrypt(
    in_path: str | _Path,
    password: str | bytes,
    *,
    out_path: str | _Path,
    verify_only: bool = False,
    progress_cb=None,
    keyfile: str | _Path | None = None,
) -> str | None:
    src = _Path(in_path)
    dst = _Path(out_path)
    if isinstance(password, str):
        password = password.encode()

    try:
        ver = _read_ver_any(src)
    except Exception:
        ver = 0

    if ver >= 5:
        from .xchacha_stream import XChaChaStream
        res = XChaChaStream().decrypt_file(
            src,
            password,
            out_path=str(dst),
            verify_only=verify_only,
            keyfile=str(keyfile) if keyfile else None,
        )
        return None if verify_only else str(_Path(res).resolve())
    else:
        # legacy v1–v4
        from .legacy.decrypt_legacy import decrypt_file as _dec_legacy
        res = _dec_legacy(src, password, out_path=str(dst), verify_only=verify_only)
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

def verify(in_path: str | _Path, password: str | bytes, *, keyfile: str | _Path | None = None) -> bool:
    """Verify authentication without leaving artifacts on disk.

    Returns True if decryption/authentication succeeds, False otherwise.
    """
    try:
        decrypt(in_path, password, out_path=_Path(in_path).with_suffix(".tmp"), verify_only=True, keyfile=keyfile)
        return True
    except Exception:
        return False
