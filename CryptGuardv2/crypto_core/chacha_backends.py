"""chacha_backends.py – ChaCha20‑Poly1305 (12 B) e XChaCha20‑Poly1305 (24 B).

Versão corrigida: remove keyword inválido `rs_bytes` nas chamadas de
`rs_encode_data` para ser compatível com implementações existentes.
"""
from __future__ import annotations

import struct
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag  # Added for tag verification
try:
    from Crypto.Cipher import ChaCha20_Poly1305  # PyCryptodome
except ImportError:
    ChaCha20_Poly1305 = None  # type: ignore

from .crypto_base import BaseCipher
from .rs_codec    import rs_encode_data, rs_decode_data
from .config      import RS_PARITY_BYTES
from crypto_core.logger import logger

TAG_LEN = 16   # bytes

class ChaChaCipher(BaseCipher):
    alg_tag       = b"CH20"
    hkdf_info     = b"PFA-keys"
    nonce_size    = 12
    use_global_hmac = True
    supports_rs   = True

    @staticmethod
    def encode_chunk(idx: int, plain: bytes, nonce: bytes, enc_key: bytes,
                     rs_use: bool, header: bytes = b"") -> Tuple[int, bytes]:
        cipher = ChaCha20Poly1305(enc_key)
        out = cipher.encrypt(nonce, plain, header)
        blob = out
        parity = RS_PARITY_BYTES if rs_use and len(blob) > RS_PARITY_BYTES else 0
        if parity:
            blob = rs_encode_data(blob, parity)
        payload = nonce + struct.pack(">I", len(blob)) + blob
        return idx, payload

    @staticmethod
    def decode_chunk(idx: int, cipher_blob: bytes, nonce: bytes, enc_key: bytes,
                     rs_use: bool, header: bytes = b"") -> Tuple[int, bytes]:
        blob = cipher_blob
        parity = RS_PARITY_BYTES if rs_use and len(blob) > RS_PARITY_BYTES else 0
        orig_blob = blob
        if parity:
            try:
                blob = rs_decode_data(blob)
            except Exception as e:
                logger.warning("RS decode failed (idx=%d, len=%d): %s – stripping %dB parity",
                               idx, len(orig_blob), e, parity)
        if parity and len(blob) <= parity + 16:
            raise ValueError("Bloco contém paridade maior ou igual ao payload; abortando.")
        last_err = None
        for attempt in ("no_strip", "strip_parity" if parity else None):
            try:
                if attempt == "strip_parity":
                    blob = orig_blob[:-parity]
                ct, tag = blob[:-16], blob[-16:]
                cipher = ChaCha20Poly1305(enc_key)
                plain = _dec(cipher, ct, tag, nonce, header)
                return idx, plain
            except Exception as e:
                last_err = e
                continue
        logger.error("Tag verification failed (idx=%d, len=%d) after %s attempts",
                     idx, len(orig_blob), 2 if parity else 1)
        raise last_err

class XChaChaCipher(BaseCipher):
    alg_tag       = b"XC20"
    hkdf_info     = b"PFA-keys"
    nonce_size    = 24
    use_global_hmac = True
    supports_rs   = True

    @staticmethod
    def encode_chunk(idx: int, plain: bytes, nonce: bytes, enc_key: bytes,
                     rs_use: bool, header: bytes = b"") -> Tuple[int, bytes]:
        if ChaCha20_Poly1305 is None:
            raise RuntimeError("PyCryptodome não encontrado – XChaCha indisponível.")
        cipher = ChaCha20_Poly1305.new(key=enc_key, nonce=nonce)
        cipher.update(header)  # aplica AAD corretamente
        ct = cipher.encrypt(plain)
        tag = cipher.digest()
        blob = ct + tag                # tag sempre 16 B; usado na decodificação
        parity = RS_PARITY_BYTES if rs_use and len(blob) > RS_PARITY_BYTES else 0
        if parity:
            blob = rs_encode_data(blob, parity)
        payload = nonce + struct.pack(">I", len(blob)) + blob
        return idx, payload

    @staticmethod
    def decode_chunk(idx: int, cipher_blob: bytes, nonce: bytes, enc_key: bytes,
                     rs_use: bool, header: bytes = b"") -> Tuple[int, bytes]:
        if ChaCha20_Poly1305 is None:
            raise RuntimeError("PyCryptodome não encontrado – XChaCha indisponível.")
        blob = cipher_blob
        parity = RS_PARITY_BYTES if rs_use and len(blob) > RS_PARITY_BYTES else 0
        orig_blob = blob
        if parity:
            try:
                blob = rs_decode_data(blob)
                orig_blob = blob
            except Exception as e:
                logger.warning("RS decode failed (idx=%d, len=%d): %s – stripping %dB parity",
                               idx, len(orig_blob), e, parity)
        if parity and len(blob) <= parity + TAG_LEN:
            raise ValueError("Bloco contém paridade maior ou igual ao payload; abortando.")
        last_err = None
        for attempt in ("no_strip", "strip_parity" if parity else None):
            try:
                if attempt == "strip_parity":
                    core = orig_blob[:-parity]
                else:
                    core = orig_blob

                if len(core) < TAG_LEN:
                    last_err = ValueError("Chunk too small for tag")
                    continue

                ct, tag = core[:-TAG_LEN], core[-TAG_LEN:]
                cipher = ChaCha20_Poly1305.new(key=enc_key, nonce=nonce)
                plain = _dec(cipher, ct, tag, nonce, header)
                return idx, plain
            except Exception as e:
                last_err = e
                continue
        logger.error("Tag verification failed (idx=%d, len=%d) after %s attempts",
                     idx, len(orig_blob), 2 if parity else 1)
        raise last_err

def _dec(cipher, ct: bytes, tag: bytes, nonce: bytes, aad: bytes) -> bytes:
    """
    Descriptografa de forma compatível com:
      • cryptography.ChaCha20Poly1305 (método decrypt, 3 args)
      • PyCryptodome ChaCha20_Poly1305 (método decrypt_and_verify, 2 args + update)
    """
    if hasattr(cipher, "decrypt_and_verify"):             # PyCryptodome
        cipher.update(aad)
        return cipher.decrypt_and_verify(ct, tag)
    else:                                                 # cryptography (ChaCha20Poly1305)
        return cipher.decrypt(nonce, ct + tag, aad)

__all__ = [
    "ChaChaCipher", "XChaChaCipher",
]