"""
Verify integrity for CG2 files (legacy v1–v4 and v5) without decrypting plaintext.
"""

from __future__ import annotations

from pathlib import Path

from .fileformat import is_cg2_file
from .factories import decrypt as _decrypt


def verify_integrity(enc_path: Path | str, password: str | bytes, profile_hint=None, *, keyfile: Path | str | None = None) -> bool:
    """Return True if the file authenticates; False otherwise.

    For v5 this uses SecretStream verify-only, for legacy it routes to the
    legacy decryptor with verify_only.
    """
    p = Path(enc_path)
    pwd = password.encode() if isinstance(password, str) else password

    if not is_cg2_file(p):
        raise ValueError("Not a CG2 file")

    try:
        _decrypt(p, pwd, out_path=str(p.with_suffix("")), verify_only=True, keyfile=str(keyfile) if keyfile else None)
        return True
    except Exception:
        return False
