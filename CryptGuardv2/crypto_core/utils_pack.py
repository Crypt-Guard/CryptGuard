from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from .utils import pack_enc_zip as _pack_enc_zip


def pack_enc_zip(
    inputs: Iterable[str | Path],
    out_zip: str | Path,
    password: str | bytes,
    *,
    algo: str = "AESG",
) -> str:
    """Compat wrapper: delega para utils.pack_enc_zip com flatten=True.

    Mantém a assinatura anterior aceitando password str|bytes.
    """
    return _pack_enc_zip(inputs, out_zip, password, algo=algo, flatten=True)

__all__ = ["pack_enc_zip"]
