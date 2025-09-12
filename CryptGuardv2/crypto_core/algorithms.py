"""
Algoritmos suportados e utilitários de normalização.

Fonte única de verdade para mapear códigos curtos <-> nomes humanos.
"""

from __future__ import annotations

from typing import Dict

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

