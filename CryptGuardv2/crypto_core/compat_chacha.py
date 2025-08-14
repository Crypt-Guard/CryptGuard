"""compat_chacha — Wrapper compatível com API de Crypto.Cipher.ChaCha20_Poly1305,
usando `cryptography` (nonce 12) e `PyNaCl` (nonce 24, XChaCha20-Poly1305).
Expondo: ChaCha20_Poly1305.new(key, nonce).encrypt_and_digest(data, ad) / decrypt_and_verify(data, tag, ad)
"""
from __future__ import annotations

from dataclasses import dataclass

TAG_LEN = 16

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as _CH20
except Exception:  # pragma: no cover
    _CH20 = None  # type: ignore

try:
    from nacl.bindings import (
        crypto_aead_xchacha20poly1305_ietf_decrypt as _x_decrypt,
    )
    from nacl.bindings import (
        crypto_aead_xchacha20poly1305_ietf_encrypt as _x_encrypt,
    )
except Exception:  # pragma: no cover
    _x_encrypt = _x_decrypt = None  # type: ignore

@dataclass
class _ChaCtx:
    key: bytes
    nonce: bytes
    ad: bytes | None = None
    xchacha: bool = False

    def encrypt_and_digest(self, data: bytes, ad: bytes | None=None) -> tuple[bytes, bytes]:
        ad = ad if ad is not None else self.ad
        if self.xchacha:
            if _x_encrypt is None:
                raise RuntimeError("PyNaCl indisponível (XChaCha20-Poly1305)")
            out = _x_encrypt(data, ad, self.nonce, self.key)
            return out[:-TAG_LEN], out[-TAG_LEN:]
        else:
            if _CH20 is None:
                raise RuntimeError("cryptography indisponível (ChaCha20-Poly1305)")
            aead = _CH20(self.key)
            out = aead.encrypt(self.nonce, data, ad)
            return out[:-TAG_LEN], out[-TAG_LEN:]

    def decrypt_and_verify(self, data: bytes, tag: bytes, ad: bytes | None=None) -> bytes:
        ad = ad if ad is not None else self.ad
        if self.xchacha:
            if _x_decrypt is None:
                raise RuntimeError("PyNaCl indisponível (XChaCha20-Poly1305)")
            return _x_decrypt(data + tag, ad, self.nonce, self.key)
        else:
            if _CH20 is None:
                raise RuntimeError("cryptography indisponível (ChaCha20-Poly1305)")
            aead = _CH20(self.key)
            return aead.decrypt(self.nonce, data + tag, ad)

class ChaCha20_Poly1305:
    @classmethod
    def new(cls, key: bytes, nonce: bytes, *, ad: bytes | None=None):
        if len(nonce) == 24:
            return _ChaCtx(key=key, nonce=nonce, ad=ad, xchacha=True)
        if len(nonce) == 12:
            return _ChaCtx(key=key, nonce=nonce, ad=ad, xchacha=False)
        raise ValueError("nonce deve ter 12 (ChaCha20-Poly1305) ou 24 bytes (XChaCha20-Poly1305)")
