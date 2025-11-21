"""
Módulo de UI para Secure Containers.

Fornece dialogs PySide6 para criar e ler containers.
"""

from .settings_containers import (
    ContainerCreateDialog,
    ContainerReadDialog,
)

__all__ = [
    "ContainerCreateDialog",
    "ContainerReadDialog",
]
