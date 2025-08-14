"""aes_backends.py – back‑ends AES‑GCM e AES‑CTR baseados em `crypto_base`.

Cada classe herda de **BaseCipher** e apenas implementa `encode_chunk` /
`decode_chunk`, delegando todo o restante (streaming, metadados, HMAC,
rate‑limiting, etc.) ao núcleo comum.
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto_core.logger import logger

from .config import RS_PARITY_BYTES
from .crypto_base import BaseCipher
from .rs_codec import rs_decode_data, rs_encode_data


class AesGcmCipher(BaseCipher):
    """AES‑256‑GCM (nonce 12 B, tag 16 B, RS opcional)."""

    alg_tag = b"AESG"
    hkdf_info = b"PFA-keys"
    nonce_size = 12
    use_global_hmac = True
    supports_rs = True

    # ------------------------------------------------------------------
    @staticmethod
    def encode_chunk(
        idx: int, plain: bytes, nonce: bytes, enc_key: bytes, rs_use: bool, header: bytes = b""
    ) -> tuple[int, bytes]:
        # validação explícita do nonce (AES-GCM requer 12 bytes)
        if len(nonce) != AesGcmCipher.nonce_size:
            raise ValueError(f"Invalid nonce length: expected {AesGcmCipher.nonce_size} bytes")
        blob = AESGCM(enc_key).encrypt(nonce, plain, header)
        parity = RS_PARITY_BYTES if rs_use and len(blob) > RS_PARITY_BYTES else 0
        if parity:
            blob = rs_encode_data(blob, parity)
        payload = nonce + struct.pack(">I", len(blob)) + blob
        return idx, payload

    # ------------------------------------------------------------------
    @staticmethod
    def decode_chunk(
        idx: int,
        cipher_blob: bytes,
        nonce: bytes,
        enc_key: bytes,
        rs_use: bool,
        header: bytes = b"",
    ) -> tuple[int, bytes]:
        if len(nonce) != AesGcmCipher.nonce_size:
            raise ValueError(f"Invalid nonce length: expected {AesGcmCipher.nonce_size} bytes")
        blob = cipher_blob
        parity = RS_PARITY_BYTES if rs_use and len(blob) > RS_PARITY_BYTES else 0
        orig_blob = blob
        if parity:
            try:
                blob = rs_decode_data(blob)
            except Exception as e:
                logger.warning(
                    "RS decode failed (idx=%d, len=%d): %s – stripping %dB parity",
                    idx,
                    len(orig_blob),
                    e,
                    parity,
                )
        last_err = None
        attempts = ("no_strip", "strip_parity") if parity else ("no_strip",)
        for attempt in attempts:
            try:
                b_use = orig_blob[:-parity] if attempt == "strip_parity" else blob
                plain = AESGCM(enc_key).decrypt(nonce, b_use, header)
                return idx, plain
            except Exception as e:
                last_err = e
                continue
        logger.error(
            "Tag verification failed (idx=%d, len=%d) after %s attempts",
            idx,
            len(orig_blob),
            len(attempts),
        )
        raise last_err


# ════════════════════════════════════════════════════════════════════════════
class AesCtrCipher(BaseCipher):
    """AES‑256‑CTR com HMAC‑SHA256 global.  RS não suportado por chunk."""

    alg_tag = b"ACTR"
    hkdf_info = b"CGv2-keys"
    nonce_size = 16
    use_global_hmac = True
    supports_rs = False

    # small helper
    @staticmethod
    def _aes_ctr(enc_key: bytes, iv: bytes):
        return Cipher(algorithms.AES(enc_key), modes.CTR(iv)).encryptor()

    # ------------------------------------------------------------------
    @staticmethod
    def encode_chunk(
        idx: int, plain: bytes, nonce: bytes, enc_key: bytes, rs_use: bool, header: bytes = b""
    ) -> tuple[int, bytes]:
        if len(nonce) != AesCtrCipher.nonce_size:
            raise ValueError(f"Invalid nonce length: expected {AesCtrCipher.nonce_size} bytes")
        enc = AesCtrCipher._aes_ctr(enc_key, nonce)
        cipher = enc.update(plain) + enc.finalize()
        payload = nonce + struct.pack(">I", len(cipher)) + cipher
        return idx, payload

    # ------------------------------------------------------------------
    @staticmethod
    def decode_chunk(
        idx: int,
        cipher_blob: bytes,
        nonce: bytes,
        enc_key: bytes,
        rs_use: bool,
        header: bytes = b"",
    ) -> tuple[int, bytes]:
        if len(nonce) != AesCtrCipher.nonce_size:
            raise ValueError(f"Invalid nonce length: expected {AesCtrCipher.nonce_size} bytes")
        # O framing externo já forneceu apenas o blob do chunk (sem length)
        cipher = cipher_blob
        dec = AesCtrCipher._aes_ctr(enc_key, nonce)
        plain = dec.update(cipher) + dec.finalize()
        # HMAC obrigatório: verificação deve ser feita no fluxo principal
        return idx, plain


__all__ = [
    "AesGcmCipher",
    "AesCtrCipher",
]
