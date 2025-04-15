# crypto_core/key_obfuscator.py
"""
KeyObfuscator - A security wrapper for cryptographic keys that
protects them in memory through obfuscation techniques.
"""

import secrets
from crypto_core.secure_bytes import SecureBytes

class KeyObfuscator:
    """
    Protects cryptographic keys in memory by splitting and obfuscating them.
    Instead of storing the key directly, it stores components that can be
    combined to recreate the key only when needed.
    """
    
    def __init__(self, key_bytes):
        if isinstance(key_bytes, SecureBytes):
            self._key = key_bytes
        else:
            self._key = SecureBytes(key_bytes)
        
        self._obfuscated = False
        self._parts = []
        self._mask = None
    
    def obfuscate(self):
        if self._obfuscated:
            return
            
        key_bytes = self._key.to_bytes()
        key_len = len(key_bytes)
        
        mask = bytearray(secrets.token_bytes(key_len))
        
        obfuscated = bytearray(key_len)
        for i in range(key_len):
            obfuscated[i] = key_bytes[i] ^ mask[i]
            
        self._mask = SecureBytes(mask)
        self._parts = [SecureBytes(obfuscated)]
        
        self._key.clear()
        self._obfuscated = True
    
    def deobfuscate(self):
        if not self._obfuscated:
            return self._key
            
        mask_bytes = self._mask.to_bytes()
        obf_bytes = self._parts[0].to_bytes()
        
        result = bytearray(len(mask_bytes))
        for i in range(len(mask_bytes)):
            result[i] = obf_bytes[i] ^ mask_bytes[i]
            
        return SecureBytes(result)
    
    def clear(self):
        if hasattr(self, '_key') and self._key:
            self._key.clear()
        
        if self._obfuscated:
            if hasattr(self, '_mask') and self._mask:
                self._mask.clear()
            if hasattr(self, '_parts'):
                for part in self._parts:
                    if part:
                        part.clear()
        
        self._parts = []
        self._mask = None
        self._obfuscated = False
    
    def __del__(self):
        self.clear()
