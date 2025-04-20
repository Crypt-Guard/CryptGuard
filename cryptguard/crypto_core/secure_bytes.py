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
    
    def __repr__(self) -> str:
        return f"<SecureBytes: {len(self)} bytes>"

def secure_password_prompt(prompt: str = "Senha: ") -> SecureBytes:
    password = getpass.getpass(prompt)
    secure_pass = SecureBytes(password)
    try:
        ctypes.memset(id(password) + sys.getsizeof(password) - len(password), 0, len(password))
    except Exception as e:
        logger.warning(f"Could not zeroize password string: {e}")
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
