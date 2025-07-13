"""
Obfuscador simples (XOR com máscara aleatória) para reduzir tempo
da chave limpa em RAM.
"""
import secrets, contextlib
from .secure_bytes import SecureBytes

class KeyObfuscator:
    __slots__ = ("_masked", "_mask")

    def __init__(self, key_sb: SecureBytes):
        self._mask   = secrets.token_bytes(len(key_sb.to_bytes()))
        self._masked = bytes(a ^ b for a, b in zip(key_sb.to_bytes(), self._mask))
        key_sb.clear()

    # ------------------------- operações base
    def deobfuscate(self) -> SecureBytes:
        plain = bytes(a ^ b for a, b in zip(self._masked, self._mask))
        return SecureBytes(plain)

    def obfuscate(self):
        # já armazenado mascarado – nada a fazer (mantido por simetria)
        pass

    def clear(self):
        self._masked = b"\x00" * len(self._masked)
        self._mask   = b"\x00" * len(self._mask)

# --------------------------- exposure helper
class TimedExposure(contextlib.AbstractContextManager):
    def __init__(self, obf: KeyObfuscator):
        self._obf = obf
        self._plain: SecureBytes | None = None
    def __enter__(self):
        self._plain = self._obf.deobfuscate()
        return self._plain
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._plain:
            self._plain.clear()
            self._plain = None
