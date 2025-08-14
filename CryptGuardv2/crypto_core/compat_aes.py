"""compat_aes — Wrapper mínimo para substituir Crypto.Cipher.AES em GCM/CTR usando `cryptography`.
Expondo: AES.new(key, MODE_GCM, nonce=...) com encrypt_and_digest/decrypt_and_verify
         AES.new(key, MODE_CTR, iv=...) com encrypt/decrypt
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MODE_GCM = 0x02
MODE_CTR = 0x05
_TAG_LEN = 16

@dataclass
class _AESGCMCtx:
    key: bytes
    nonce: bytes

    def encrypt_and_digest(self, data: bytes, ad: bytes | None=None) -> tuple[bytes, bytes]:
        aead = AESGCM(self.key)
        out = aead.encrypt(self.nonce, data, ad)
        return out[:-_TAG_LEN], out[-_TAG_LEN:]

    def decrypt_and_verify(self, data: bytes, tag: bytes, ad: bytes | None=None) -> bytes:
        aead = AESGCM(self.key)
        return aead.decrypt(self.nonce, data + tag, ad)

@dataclass
class _AESCTRCtx:
    cipher: Cipher
    def encrypt(self, data: bytes) -> bytes:
        return self.cipher.encryptor().update(data) + b""
    def decrypt(self, data: bytes) -> bytes:
        return self.cipher.decryptor().update(data) + b""

class AES:
    MODE_GCM = MODE_GCM
    MODE_CTR = MODE_CTR
    @classmethod
    def new(cls, key: bytes, mode: int, **kw):
        if mode == MODE_GCM:
            nonce = kw.get("nonce") or kw.get("iv")
            if not isinstance(nonce, bytes | bytearray) or len(nonce) not in (12, 16):
                raise ValueError("nonce/iv inválido para GCM")
            return _AESGCMCtx(key=bytes(key), nonce=bytes(nonce))
        if mode == MODE_CTR:
            iv = kw.get("nonce") or kw.get("iv")
            if not isinstance(iv, bytes | bytearray):
                raise ValueError("iv ausente para CTR")
            cipher = Cipher(algorithms.AES(bytes(key)), modes.CTR(bytes(iv)))
            return _AESCTRCtx(cipher=cipher)
        raise ValueError("modo AES não suportado: use MODE_GCM ou MODE_CTR")
