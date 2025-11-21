"""
Módulo de integração entre containers e vaults.

Fornece funções para coletar itens dos vaults e integrar
itens de containers nos vaults.
"""

from .container_bridge import (
    IntegrateReport,
    collect_from_cryptguard,
    collect_from_keyguard,
    integrate_into_cryptguard,
    integrate_into_keyguard,
)

__all__ = [
    "collect_from_cryptguard",
    "collect_from_keyguard",
    "integrate_into_cryptguard",
    "integrate_into_keyguard",
    "IntegrateReport",
]

