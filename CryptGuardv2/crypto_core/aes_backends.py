"""aes_backends.py – back‑ends AES‑GCM e AES‑CTR baseados em `crypto_base`.

Cada classe herda de **BaseCipher** e apenas implementa `encode_chunk` /
`decode_chunk`, delegando todo o restante (streaming, metadados, HMAC,
rate‑limiting, etc.) ao núcleo comum.
"""
from __future__ import annotations

import struct
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

from .crypto_base      import BaseCipher
from .rs_codec         import rs_encode_data, rs_decode_data
from .config           import RS_PARITY_BYTES
from crypto_core.logger import logger

class AesGcmCipher(BaseCipher):
    """AES‑256‑GCM (nonce 12 B, tag 16 B, RS opcional)."""
    alg_tag       = b"AESG"
    hkdf_info     = b"PFA-keys"
    nonce_size    = 12
    use_global_hmac = True
    supports_rs   = True

    # ------------------------------------------------------------------
    @staticmethod
    def encode_chunk(idx: int, plain: bytes, nonce: bytes, enc_key: bytes,
                     rs_use: bool, header: bytes = b"") -> Tuple[int, bytes]:
        blob = AESGCM(enc_key).encrypt(nonce, plain, header)
        parity = RS_PARITY_BYTES if rs_use and len(blob) > RS_PARITY_BYTES else 0
        if parity:
            blob = rs_encode_data(blob, parity)
        payload = nonce + struct.pack(">I", len(blob)) + blob
        return idx, payload

    # ------------------------------------------------------------------
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
                logger.warning(
                    "RS decode failed (idx=%d, len=%d): %s – stripping %dB parity",
                    idx, len(orig_blob), e, parity
                )
        # Bloqueio de RS inválido
        if parity and len(blob) <= parity + 16:
            raise ValueError("Bloco contém paridade maior ou igual ao payload; abortando.")
        last_err = None
        attempts = ["no_strip"]
        if parity:
            attempts.append("strip_parity")
        for attempt in attempts:
            try:
                b_use = orig_blob[:-parity] if attempt == "strip_parity" else blob
                plain = AESGCM(enc_key).decrypt(nonce, b_use, header)
                return idx, plain
            except InvalidTag as e:
                last_err = e
                continue
        logger.error("Tag verification failed (idx=%d, len=%d) after %s attempts",
                     idx, len(orig_blob), len(attempts))
        raise last_err

# ════════════════════════════════════════════════════════════════════════════
class AesCtrCipher(BaseCipher):
    """AES‑256‑CTR com HMAC‑SHA256 global.  RS não suportado por chunk."""
    alg_tag       = b"ACTR"
    hkdf_info     = b"CGv2-keys"
    nonce_size    = 16
    use_global_hmac = True
    supports_rs   = False

    # small helper
    @staticmethod
    def _aes_ctr(enc_key: bytes, iv: bytes):
        return Cipher(algorithms.AES(enc_key), modes.CTR(iv),
                      backend=default_backend()).encryptor()

    # ------------------------------------------------------------------
    @staticmethod
    def encode_chunk(idx: int, plain: bytes, nonce: bytes, enc_key: bytes,
                     rs_use: bool, header: bytes = b"") -> Tuple[int, bytes]:
        enc = AesCtrCipher._aes_ctr(enc_key, nonce)
        cipher = enc.update(plain) + enc.finalize()
        payload = nonce + struct.pack(">I", len(cipher)) + cipher
        return idx, payload

    # ------------------------------------------------------------------
    @staticmethod
    def decode_chunk(idx: int, cipher_blob: bytes, nonce: bytes, enc_key: bytes,
                     rs_use: bool, header: bytes = b"") -> Tuple[int, bytes]:
        (clen,) = struct.unpack(">I", cipher_blob[:4])
        cipher  = cipher_blob[4:4+clen]
        dec = AesCtrCipher._aes_ctr(enc_key, nonce)
        plain = dec.update(cipher) + dec.finalize()
        # HMAC obrigatório: verificação deve ser feita no fluxo principal
        return idx, plain

__all__ = [
    "AesGcmCipher", "AesCtrCipher",
]
