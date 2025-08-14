"""
Verifica a integridade de arquivos .cg2 via AEAD/footer (sem descriptografar payload).
"""

from __future__ import annotations

from pathlib import Path

from .cg2_ops import decrypt_from_cg2
from .fileformat import is_cg2_file


def verify_integrity(enc_path: Path | str, password: str | bytes, profile_hint=None) -> bool:
    """Valida integridade/expiração para CG2.

    Args:
        enc_path: caminho para arquivo `.cg2`.
        password: senha (str ou bytes).
        profile_hint: ignorado aqui (mantido por compatibilidade).

    Returns:
        True se as tags (e expiração do header) forem válidas; False caso contrário.

    Levanta:
        ValueError: se o arquivo não for CG2.
    """
    p = Path(enc_path)
    pwd = password.encode() if isinstance(password, str) else password

    if not is_cg2_file(p):
        raise ValueError("Not a CG2 file")

    try:
        # Em CG2, a verificação é feita via AEAD/rodapé (verify_only=True)
        return bool(decrypt_from_cg2(p, "", pwd, verify_only=True))
    except Exception:
        return False
