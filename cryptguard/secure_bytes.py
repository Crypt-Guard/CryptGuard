"""
secure_bytes.py – Módulo unificado para proteção segura de dados sensíveis no CryptGuard

Este módulo junta as implementações de SecureBytes e funções auxiliares (como secure_password_prompt,
with_secure_context, secure_string_to_bytes e wipe_sensitive_data), combinando as melhores
práticas de ambas as versões apresentadas anteriormente.

A classe SecureBytes armazena os dados em um bytearray mutável, permitindo que sejam sobrescritos
(zerados) explicitamente. Além disso, há funções de suporte para converter strings em SecureBytes,
solicitar senhas de forma segura e limpar dados sensíveis.
"""

import os
import sys
import secrets
import ctypes
import getpass
from typing import Optional, Union, Any, Callable
import logging

# Configuração básica de logging (opcional)
logger = logging.getLogger("cryptguard.secure_memory")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(handler)

class SecureBytes:
    """
    Secure container for sensitive byte data with explicit zeroization capabilities.
    
    This class combines elements from two previous implementations:
      - It stores sensitive data in a mutable bytearray (allowing in‑place overwrite).
      - It provides a clear() method that zeros out the data.
      - It includes a wipe() method as a best-effort alternative that overwrites the data with random bytes.
    """
    def __init__(self, data: Optional[Union[bytes, bytearray, str]] = None, length: Optional[int] = None):
        """
        Initialize the SecureBytes container.
        
        Args:
            data: The initial data (as bytes, bytearray, or string). If a string is provided, it will be encoded as UTF-8.
            length: If no data is provided, allocate a secure buffer of this length filled with random bytes.
        """
        if data is not None:
            if isinstance(data, str):
                # Encode string to bytes using UTF-8
                self._data = bytearray(data.encode('utf-8'))
            elif isinstance(data, (bytes, bytearray)):
                # Always store as mutable bytearray
                self._data = bytearray(data)
            else:
                raise TypeError("Data must be bytes, bytearray, or str")
        elif length is not None:
            # Allocate a buffer of the given length filled with random bytes
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
        """
        Get a copy of the secure data.
        """
        return self.to_bytes()
    
    def clear(self) -> None:
        """
        Securely clear the data by overwriting with zeros, then remove the reference.
        """
        if self._data is not None:
            for i in range(len(self._data)):
                self._data[i] = 0
            # Remove the reference
            self._data = bytearray()
    
    def wipe(self) -> None:
        """
        Securely wipe the data by overwriting with random bytes (best-effort) before clearing.
        This may provide additional obfuscation compared to simply zeroing the memory.
        """
        if self._data is not None:
            random_bytes = os.urandom(len(self._data))
            # Overwrite with random data
            for i in range(len(self._data)):
                self._data[i] = random_bytes[i]
            self.clear()
    
    def __len__(self) -> int:
        return len(self._data) if self._data is not None else 0
    
    def __del__(self):
        self.clear()
    
    def __repr__(self) -> str:
        # Do not reveal sensitive data in the representation
        return f"<SecureBytes: {len(self)} bytes>"


def secure_password_prompt(prompt: str = "Senha: ") -> SecureBytes:
    """
    Solicita uma senha ao usuário de forma segura e retorna como SecureBytes.
    
    Args:
        prompt: Texto a ser exibido na solicitação.
    
    Returns:
        SecureBytes: A senha fornecida pelo usuário.
    """
    password = getpass.getpass(prompt)
    secure_pass = SecureBytes(password)
    # Tenta zeroizar a string original da senha – esta operação é melhor-effort.
    try:
        ctypes.memset(id(password) + sys.getsizeof(password) - len(password), 0, len(password))
    except Exception as e:
        logger.warning(f"Could not zeroize password string: {e}")
    return secure_pass


def secure_string_to_bytes(s: str) -> SecureBytes:
    """
    Converte uma string em SecureBytes.
    
    Args:
        s: A string a ser convertida.
    
    Returns:
        SecureBytes: Conteúdo da string em forma protegida.
    """
    sb = SecureBytes(s)
    # Optionally, we can try to wipe the original string reference afterward.
    s = "0" * len(s)
    return sb


def wipe_sensitive_data(variable: Any) -> None:
    """
    Tenta limpar uma variável que contenha dados sensíveis.
    
    Args:
        variable: A variável a ser limpa, se suportar zeroização.
    """
    if isinstance(variable, SecureBytes):
        variable.clear()
    elif isinstance(variable, bytearray):
        for i in range(len(variable)):
            variable[i] = 0
    # For immutable types, cannot zero in-place – simply remove reference.
    # In all cases, set the variable to None.
    variable = None


def with_secure_context(func: Callable) -> Callable:
    """
    Decorator to automatically manage SecureBytes cleanup.
    It collects any SecureBytes arguments and allows you to zeroize them after function execution.
    
    Note: In this example, the decorator only outlines the intended behavior. The actual zeroization must be managed
    by the function or returned objects as appropriate.
    
    Args:
        func: A function that receives SecureBytes objects.
    
    Returns:
        Callable: The decorated function.
    """
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
            # Optionally, zeroize temporary SecureBytes objects if desired.
            for obj in secure_objects:
                pass  # The caller can decide when to clear them explicitly.
    return wrapper
