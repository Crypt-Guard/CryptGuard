"""
KeyObfuscator - A security wrapper for cryptographic keys that
protects them in memory through obfuscation techniques.
"""
import secrets
from secure_bytes import SecureBytes

class KeyObfuscator:
    """
    Protects cryptographic keys in memory by splitting and obfuscating them.
    Instead of storing the key directly, it stores components that can be
    combined to recreate the key only when needed.
    """
    
    def __init__(self, key_bytes):
        """
        Initialize with a key (SecureBytes or bytes-like object)
        
        Args:
            key_bytes: SecureBytes or bytes-like object containing the key to protect
        """
        if isinstance(key_bytes, SecureBytes):
            self._key = key_bytes
        else:
            self._key = SecureBytes(key_bytes)
        
        # Initialize all attributes to prevent errors during cleanup
        self._obfuscated = False
        self._parts = []
        self._mask = None
    
    def obfuscate(self):
        """
        Obfuscate the key in memory by splitting it into multiple parts
        with an XOR mask.
        """
        if self._obfuscated:
            return
            
        key_bytes = self._key.to_bytes()
        key_len = len(key_bytes)
        
        # Create a random mask the same size as the key
        mask = bytearray(secrets.token_bytes(key_len))
        
        # Create obfuscated version (key XOR mask)
        obfuscated = bytearray(key_len)
        for i in range(key_len):
            obfuscated[i] = key_bytes[i] ^ mask[i]
            
        # Store parts securely
        self._mask = SecureBytes(mask)
        self._parts = [SecureBytes(obfuscated)]
        
        # Clear original key
        self._key.clear()
        self._obfuscated = True
    
    def deobfuscate(self):
        """
        Temporarily reconstruct the key for use in cryptographic operations.
        Returns a SecureBytes object containing the original key.
        
        Returns:
            SecureBytes: The reconstructed original key
        """
        if not self._obfuscated:
            return self._key
            
        # Reconstruct key from parts
        mask_bytes = self._mask.to_bytes()
        obf_bytes = self._parts[0].to_bytes()
        
        # XOR to get original
        result = bytearray(len(mask_bytes))
        for i in range(len(mask_bytes)):
            result[i] = obf_bytes[i] ^ mask_bytes[i]
            
        return SecureBytes(result)
    
    def clear(self):
        """
        Securely clear all key material from memory
        """
        # Make sure attributes exist before accessing them
        if hasattr(self, '_key') and self._key:
            self._key.clear()
        
        if hasattr(self, '_obfuscated') and self._obfuscated:
            if hasattr(self, '_mask') and self._mask:
                self._mask.clear()
            
            if hasattr(self, '_parts'):
                for part in self._parts:
                    if part:
                        part.clear()
        
        # Reset to safe state
        self._parts = []
        self._mask = None
        self._obfuscated = False
    
    def __del__(self):
        """
        Ensure all sensitive data is cleared when the object is destroyed
        """
        self.clear()
