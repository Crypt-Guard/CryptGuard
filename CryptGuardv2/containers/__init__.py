"""
Módulo de Secure Containers para compartilhamento seguro.

Este módulo implementa o formato de container .vault que permite
transportar de forma segura itens do CryptGuard e KeyGuard.
"""

from .secure_container import (
    ContainerEntry,
    SecureContainerReader,
    SecureContainerWriter,
)
from .storage_atomic import acquire_lock, atomic_save

__all__ = [
    "SecureContainerWriter",
    "SecureContainerReader",
    "ContainerEntry",
    "acquire_lock",
    "atomic_save",
]

