#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Safe wrapper to work with KeyObfuscator without relying on private attributes.
Used by KeyGuard and CryptGuard.
"""
from __future__ import annotations

import warnings
from typing import Optional

# Prefer the project's SecureBytes, fallback to a simple zeroizable buffer
try:
    from crypto_core.secure_bytes import SecureBytes as SecureMemory  # type: ignore
except Exception:
    class SecureMemory:  # type: ignore
        def __init__(self, b: bytes):
            self._b = bytearray(b)
        def get_bytes(self) -> bytes:
            return bytes(self._b)
        def clear(self) -> None:
            for i in range(len(self._b)):
                self._b[i] = 0

try:
    from crypto_core.key_obfuscator import KeyObfuscator  # type: ignore
except Exception:
    class KeyObfuscator:  # type: ignore
        def __init__(self, sm: SecureMemory):
            self._sm = sm
            self._obf = False
        def obfuscate(self) -> None:
            self._obf = True
        def deobfuscate(self) -> None:
            self._obf = False
        def clear(self) -> None:
            try:
                self._sm.clear()
            except Exception:
                pass

class TimedExposure:
    """deobfuscate -> expose SecureMemory -> reobfuscate"""
    def __init__(self, get_sm, deobf=None, obf=None):
        self._get_sm = get_sm
        self._deobf = deobf
        self._obf = obf
    def __enter__(self) -> SecureMemory:
        try:
            if callable(self._deobf):
                self._deobf()
        except Exception:
            pass
        return self._get_sm()
    def __exit__(self, *_exc) -> None:
        try:
            if callable(self._obf):
                self._obf()
        except Exception:
            pass

class ObfuscatedSecret:
    """
    Holds SecureMemory and uses KeyObfuscator only to (de)obfuscate,
    without touching any private attributes.
    """
    def __init__(self, sm):
        # Aviso de segurança: ObfuscatedSecret pode não oferecer ofuscação real
        warnings.warn(
            "ObfuscatedSecret: nem sempre oferece ofuscação real - depende da disponibilidade do KeyObfuscator.",
            RuntimeWarning, stacklevel=2
        )
        # Guardar referência ao SecureMemory original
        self._sm = sm
        # Instanciar KeyObfuscator quando disponível
        try:
            self._ko = KeyObfuscator(self._sm)  # type: ignore
        except Exception:
            self._ko = None

    def _obfuscate(self) -> None:
        try:
            if self._ko and hasattr(self._ko, "obfuscate"):
                self._ko.obfuscate()
        except Exception:
            pass

    def _deobfuscate(self) -> None:
        # Transformado em no-op: expose() já delega ao KeyObfuscator
        pass

    def expose(self) -> TimedExposure:
        # Evita "SecureBytes already cleared" ao clonar via .to_bytes()
        def _getter():
            return self._sm
        if self._ko is not None and hasattr(self._ko, 'expose'):
            # delega ao KeyObfuscator para exposição temporária do plaintext
            return self._ko.expose()  # type: ignore
        return TimedExposure(_getter, self._deobfuscate, self._obfuscate)

    def clear(self) -> None:
        try:
            if self._ko and hasattr(self._ko, "clear"):
                self._ko.clear()
        except Exception:
            pass
        try:
            self._sm.clear()
        except Exception:
            pass

    def reset(self, new_sm: SecureMemory) -> None:
        self.clear()
        self._sm = new_sm
        try:
            self._ko = KeyObfuscator(self._sm)  # type: ignore
        except Exception:
            self._ko = None
        self._obfuscate()

def sm_get_bytes(sm) -> bytes:
    """
    Extrai bytes de um SecureMemory/SecureBytes SEM chamar to_bytes().
    Ordem: get_bytes() -> view() -> _b -> _buf -> bytes(sm) -> erro.
    """
    # API moderna: get_bytes()
    get = getattr(sm, "get_bytes", None)
    if callable(get):
        try:
            return get()
        except Exception:
            pass

    # Alguns expõem .view() (memoryview) - especialmente SecureBytes
    view = getattr(sm, "view", None)
    if callable(view):
        try:
            mv = view()
            return bytes(mv)
        except Exception:
            pass

    # Fallbacks a atributos internos comuns
    b = getattr(sm, "_b", None)
    if isinstance(b, (bytes, bytearray, memoryview)):
        try:
            return bytes(b)
        except Exception:
            pass

    buf = getattr(sm, "_buf", None)
    if isinstance(buf, (bytes, bytearray, memoryview)):
        try:
            return bytes(buf)
        except Exception:
            pass

    # Último recurso: construtor bytes() — inseguro (cópia não zeroizável)
    import warnings as _warn
    _warn.warn('sm_get_bytes: gerando bytes() não-zeroizável (último recurso)', RuntimeWarning, stacklevel=2)
    try:
        return bytes(sm)
    except Exception:
        pass

    raise TypeError("Cannot extract bytes from SecureMemory-like object")

__all__ = ["SecureMemory", "KeyObfuscator", "TimedExposure", "ObfuscatedSecret", "sm_get_bytes"]
