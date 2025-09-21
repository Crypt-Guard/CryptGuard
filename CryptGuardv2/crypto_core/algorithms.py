"""
DEPRECATED MODULE
-----------------
Maintained only for backward compatibility with v1-v4 containers.
Runtime in v5 always uses the fixed XChaCha20-Poly1305 SecretStream.
"""

from __future__ import annotations

import warnings
from typing import Dict

warnings.warn(
    "crypto_core.algorithms is deprecated; v5 uses a fixed XChaCha20-Poly1305 SecretStream.",
    DeprecationWarning,
    stacklevel=2,
)

# Códigos curtos -> nomes humanos
SHORT_TO_HUMAN: Dict[str, str] = {
    "AESG": "AES-256-GCM",
    "ACTR": "AES-256-CTR",
    "XC20": "XChaCha20-Poly1305",
    "CH20": "ChaCha20-Poly1305",
}

# Nomes humanos -> códigos curtos
HUMAN_TO_SHORT: Dict[str, str] = {v: k for k, v in SHORT_TO_HUMAN.items()}


def normalize_algo(a: str) -> str:
    """Normaliza entrada para o nome humano do algoritmo.

    Aceita códigos curtos (AESG/ACTR/XC20/CH20) ou já o nome humano.
    Lança ValueError se não suportado.
    """
    if not a:
        raise ValueError("Algoritmo não especificado")
    up = a.strip()
    # tenta código curto (case-insensitive)
    short = up.upper()
    if short in SHORT_TO_HUMAN:
        return SHORT_TO_HUMAN[short]
    # aceita exatamente nomes humanos conhecidos
    if up in HUMAN_TO_SHORT:
        return up
    raise ValueError(f"Algoritmo não suportado: {a!r}. Use AESG|ACTR|XC20|CH20.")


__all__ = ["SHORT_TO_HUMAN", "HUMAN_TO_SHORT", "normalize_algo"]

