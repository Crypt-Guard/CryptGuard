"""
Verify integrity for CG2 files (legacy v1–v4 and v5) without decrypting plaintext.
"""

from __future__ import annotations

from pathlib import Path
import tempfile

from .fileformat import is_cg2_file
from .factories import decrypt as _decrypt


def verify_integrity(
    enc_path: Path | str,
    password: str | bytes,
    *,
    keyfile: Path | str | None = None,
) -> bool:
    """Return True if the file authenticates; False otherwise.

    For v5 this uses SecretStream verify-only, for legacy it routes to the
    legacy decryptor with verify_only.
    """
    p = Path(enc_path)
    pwd = password.encode() if isinstance(password, str) else password

    if not is_cg2_file(p):
        raise ValueError("Not a CG2 file")

    try:
        # use um caminho temporário por robustez, mesmo em verify_only
        with tempfile.TemporaryDirectory() as td:
            dummy_out = Path(td) / "cg2_verify_sink"
            _decrypt(
                p,
                pwd,
                out_path=str(dummy_out),
                verify_only=True,
                keyfile=str(keyfile) if keyfile else None,
            )
        return True
    except Exception:
        return False
