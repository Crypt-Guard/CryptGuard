"""
cg2_ops.py — *compat shim* para a versão atual (v5 SecretStream)

Este módulo mantém a **assinatura pública** das funções antigas
(`encrypt_to_cg2`, `decrypt_from_cg2`) porém **delegando** para o
pipeline atual do projeto (writer/reader v5).

Motivação:
- Remover complexidade e backends antigos (AES-GCM, ChaCha, CTR+HMAC)
- Evitar divergência de lógica; um único caminho de escrita/leitura
- Preservar compat nas camadas que ainda importam cg2_ops.*
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from . import factories
from .config import CG2_EXT, SecurityProfile

# OBS: toda a lógica multi-algoritmo, footers (END0/NAM0/SIZ0/TAG0),
# HKDF auxiliares e heurísticas de extensão foram removidas. Hoje
# quem cuida de streaming + metadados é o writer v5 (SecretStream).


def encrypt_to_cg2(
    in_path: str | Path,
    out_path: str | Path,
    password: bytes,
    alg: str = "SecretStream",
    profile: SecurityProfile = SecurityProfile.BALANCED,
    exp_ts: int | None = None,
    *,
    progress_cb: Callable[[int], None] | None = None,
    pad_block: int = 0,
) -> Path:
    """
    Compat wrapper para a criptografia **v5 SecretStream**.
    Parâmetros mantidos por compat; `alg` é ignorado.
    """
    in_path = Path(in_path)
    out_path = Path(out_path)
    if out_path.suffix.lower() != CG2_EXT:
        out_path = out_path.with_suffix(CG2_EXT)

    # Delegação para o writer v5 (SecretStream). Parâmetros padronizados.
    result = factories.encrypt(
        in_path=in_path,
        out_path=out_path,
        password=password,
        algo=alg,
        profile=profile,
        exp_ts=exp_ts,
        pad_block=pad_block,
        progress_cb=progress_cb,
    )
    return Path(result)


def decrypt_from_cg2(
    in_path: str | Path,
    out_path: str | Path,
    password: bytes,
    verify_only: bool = False,
    *,
    progress_cb: Callable[[int], None] | None = None,
) -> Path | bool:
    """
    Compat wrapper para **decrypt/verify** do pipeline atual.
    """
    result = factories.decrypt(
        in_path=Path(in_path),
        out_path=Path(out_path),
        password=password,
        verify_only=verify_only,
        progress_cb=progress_cb,
    )

    if verify_only:
        return result is not None  # True se sucesso, False se falhou
    else:
        return Path(result) if result else Path(out_path)


__all__ = ["encrypt_to_cg2", "decrypt_from_cg2"]
