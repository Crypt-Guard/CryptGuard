from __future__ import annotations

from pathlib import Path


def decrypt_file(
    in_path: str | Path,
    password: bytes | str,
    *,
    out_path: str | Path,
    verify_only: bool = False,
):
    """Thin wrapper to the existing v1–v4 decryptor in cg2_ops.

    Keeps legacy code isolated under crypto_core.legacy.* namespace for read-only.
    """
    from ..cg2_ops import decrypt_from_cg2 as _dec

    src = Path(in_path)
    dst = Path(out_path)
    pwd = password.encode() if isinstance(password, str) else password
    return _dec(src, dst, pwd, verify_only=verify_only)


__all__ = ["decrypt_file"]
