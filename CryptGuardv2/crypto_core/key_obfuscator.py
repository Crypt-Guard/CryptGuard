"""
Obfuscador simples (XOR com máscara aleatória) para reduzir tempo
da chave limpa em RAM.
"""
import secrets, contextlib
from .secure_bytes import SecureBytes
import ctypes

class KeyObfuscator:
    __slots__ = ("_masked", "_mask", "_cleared")

    def __init__(self, key_sb: SecureBytes):
        # minimizar cópias de plaintext e usar buffers mutáveis
        plain = key_sb.to_bytes()
        if not plain:
            key_sb.clear()
            raise ValueError("Empty key is not allowed")
        self._mask   = bytearray(secrets.token_bytes(len(plain)))
        self._masked = bytearray(a ^ b for a, b in zip(plain, self._mask))
        self._cleared = False
        key_sb.clear()
        del plain

    # helper para zerar bytearrays de forma segura
    @staticmethod
    def _memzero(buf: bytearray):
        if buf:
            ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buf)), 0, len(buf))

    @property
    def cleared(self) -> bool:
        # redundante com checagens de buffers vazios, mas explícito
        return self._cleared or not self._mask or not self._masked

    # ------------------------- operações base
    def deobfuscate(self) -> SecureBytes:
        if self.cleared:
            raise RuntimeError("Key material has been cleared or is invalid")
        plain = bytes(a ^ b for a, b in zip(self._masked, self._mask))
        return SecureBytes(plain)

    def obfuscate(self):
        # re-mascarar sem materializar plaintext: masked' = masked ^ mask ^ new_mask
        if self.cleared:
            return
        n = len(self._mask)
        new_mask = bytearray(secrets.token_bytes(n))
        for i in range(n):
            self._masked[i] ^= self._mask[i] ^ new_mask[i]
        self._memzero(self._mask)
        self._mask = new_mask

    def clear(self):
        # zerar os buffers reais em lugar (antes criava cópias e não limpava o original)
        if self._cleared:
            return
        self._memzero(self._masked)
        self._memzero(self._mask)
        self._masked.clear(); self._mask.clear()
        self._cleared = True

    def expose(self) -> "TimedExposure":
        # helper para uso: with obf.expose() as key: ...
        return TimedExposure(self)

    def __del__(self):
        with contextlib.suppress(Exception):
            self.clear()

# --------------------------- exposure helper
class TimedExposure(contextlib.AbstractContextManager):
    def __init__(self, obf: KeyObfuscator):
        self._obf = obf
        self._plain: SecureBytes | None = None
    def __enter__(self):
        if self._plain is not None:
            raise RuntimeError("Re-entrant exposure is not allowed")
        if self._obf.cleared:
            raise RuntimeError("Cannot expose a cleared KeyObfuscator")
        self._plain = self._obf.deobfuscate()
        return self._plain
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._plain:
            self._plain.clear()
            self._plain = None
