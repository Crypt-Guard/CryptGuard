from __future__ import annotations

# kdf_v5.py — compat shim
import warnings

from .kdf import (
    INTERACTIVE,
    SENSITIVE,
    KDFProfile,
    derive_key_and_params,
    derive_key_from_params,
    derive_key_from_params_json,
    derive_key_v5,
)

warnings.warn(
    "crypto_core.kdf_v5 foi unificado em crypto_core.kdf (v5-first). "
    "Atualize seus imports para 'from crypto_core.kdf import ...'.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "derive_key_v5",
    "derive_key_from_params_json",
    "KDFProfile",
    "INTERACTIVE",
    "SENSITIVE",
    "derive_key_and_params",
    "derive_key_from_params",
]
