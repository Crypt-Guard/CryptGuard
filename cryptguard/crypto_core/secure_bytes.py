# crypto_core/secure_bytes.py
"""
secure_bytes.py - Unified module for secure protection of sensitive data in CryptGuard

This module combines SecureBytes implementations and auxiliary functions,
combining best practices from both previously presented versions.

The SecureBytes class stores data in a mutable bytearray, allowing it to
be explicitly overwritten (zeroed). Additionally, there are support functions
for converting strings to SecureBytes, securely requesting passwords, and clearing sensitive data.
"""

import os
import sys
import secrets
import ctypes
import platform
import getpass
from typing import Optional, Union, Any, Callable
import logging

logger = logging.getLogger("cryptguard.secure_memory")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

class SecureBytes:
    """
    Secure container for sensitive byte data with explicit zeroization capabilities.
    """
    def __init__(self, data: Optional[Union[bytes, bytearray, str]] = None, length: Optional[int] = None):
        if data is not None:
            if isinstance(data, str):
                self._data = bytearray(data.encode('utf-8'))
            elif isinstance(data, (bytes, bytearray)):
                self._data = bytearray(data)
            else:
                raise TypeError("Data must be bytes, bytearray, or str")
        elif length is not None:
            self._data = bytearray(secrets.token_bytes(length))
        else:
            self._data = bytearray()

        self._size = len(self._data)
        self._locked = False
        self._protected = False

        self._protect_memory()
    
    def _protect_memory(self) -> None:
        if self._size == 0:
            return
        try:
            address = ctypes.addressof(ctypes.c_char.from_buffer(self._data))
            if platform.system() == "Windows":
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                if kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(self._size)):
                    self._locked = True
                    logger.debug("Mem\xF3ria protegida com VirtualLock")
                else:
                    err = ctypes.get_last_error()
                    logger.warning("VirtualLock falhou (%d)", err)
                handle = kernel32.GetCurrentProcess()
                if hasattr(kernel32, "SetProcessWorkingSetSize"):
                    kernel32.SetProcessWorkingSetSize(handle, -1, -1)
            else:
                libc = ctypes.CDLL(None)
                if libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(self._size)) == 0:
                    self._locked = True
                    logger.debug("Mem\xF3ria protegida com mlock")
                else:
                    errno = ctypes.get_errno()
                    logger.warning("mlock falhou (errno %d)", errno)
                try:
                    MCL_CURRENT = 1
                    MCL_FUTURE = 2
                    libc.mlockall(MCL_CURRENT | MCL_FUTURE)
                except Exception:
                    pass
            self._protected = True
        except Exception as e:
            logger.warning("Prote\xE7\xE3o de mem\xF3ria indispon\xEDvel: %s", e)

    def to_bytes(self) -> bytes:
        """
        Returns an immutable copy of the secure data.
        """
        if self._data is None:
            return b""
        return bytes(self._data)
    
    def get(self) -> bytes:
        return self.to_bytes()
    
    def clear(self) -> None:
        if self._data is not None:
            for i in range(len(self._data)):
                self._data[i] = 0
            self._data = bytearray()

        if self._locked:
            try:
                address = ctypes.addressof(ctypes.c_char.from_buffer(self._data))
                if platform.system() == "Windows":
                    kernel32 = ctypes.WinDLL("kernel32")
                    kernel32.VirtualUnlock(ctypes.c_void_p(address), ctypes.c_size_t(self._size))
                else:
                    libc = ctypes.CDLL(None)
                    libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(self._size))
            except Exception:
                pass

        self._size = 0
        self._locked = False
        self._protected = False

    def wipe(self) -> None:
        if self._data is not None:
            random_bytes = os.urandom(len(self._data))
            for i in range(len(self._data)):
                self._data[i] = random_bytes[i]
            self.clear()
    
    def __len__(self) -> int:
        return len(self._data) if self._data is not None else 0
    
    def __del__(self):
        self.clear()

    @property
    def is_protected(self) -> bool:
        return self._locked
    
    def __repr__(self) -> str:
        return f"<SecureBytes: {len(self)} bytes>"

def secure_password_prompt(prompt: str = "Senha: ") -> SecureBytes:
    password = getpass.getpass(prompt)
    secure_pass = SecureBytes(password)
    try:
        password_id = id(password)
        password_len = len(password)
        buffer_offset = sys.getsizeof(password) - password_len - 1
        buffer_addr = password_id + buffer_offset
        ctypes.memset(buffer_addr, 0, password_len)
    except Exception as e:
        logger.debug("N\xE3o foi poss\xEDvel limpar string da mem\xF3ria: %s", e)
    return secure_pass

def secure_string_to_bytes(s: str) -> SecureBytes:
    sb = SecureBytes(s)
    s = "0" * len(s)
    return sb

def wipe_sensitive_data(variable: Any) -> None:
    if isinstance(variable, SecureBytes):
        variable.clear()
    elif isinstance(variable, bytearray):
        for i in range(len(variable)):
            variable[i] = 0
    variable = None

def with_secure_context(func: Callable) -> Callable:
    def wrapper(*args, **kwargs):
        secure_objects = []
        for arg in args:
            if isinstance(arg, SecureBytes):
                secure_objects.append(arg)
        for key, value in kwargs.items():
            if isinstance(value, SecureBytes):
                secure_objects.append(value)
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            for obj in secure_objects:
                pass  # O chamador decide quando limpar
    return wrapper
