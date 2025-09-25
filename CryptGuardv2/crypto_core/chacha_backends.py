from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from crypto_core.logger import logger

from .config import RS_PARITY_BYTES
from .crypto_base import BaseCipher
from .rs_codec import rs_decode_data, rs_encode_data

try:
    from crypto_core.compat_chacha import ChaCha20_Poly1305  # PyCryptodome
except ImportError:
    ChaCha20_Poly1305 = None  # type: ignore

# nosec B413: # # import Crypto  # removido pela migração  # removed by migration legado — backends preferidos são cryptography/PyNaCl; mantido por compat.
"""chacha_backends.py – ChaCha20‑Poly1305 (12 B) e XChaCha20‑Poly1305 (24 B).

Versão corrigida: remove keyword inválido `rs_bytes` nas chamadas de
`rs_encode_data` para ser compatível com implementações existentes.
"""

TAG_LEN = 16  # bytes


class ChaChaCipher(BaseCipher):
    alg_tag = b"CH20"
    hkdf_info = b"PFA-keys"
    nonce_size = 12
    use_global_hmac = True
    supports_rs = True

    @staticmethod
    def encode_chunk(
        idx: int,
        plain: bytes,
        nonce: bytes,
        enc_key: bytes,
        rs_use: bool,
        header: bytes = b"",
    ) -> tuple[int, bytes]:
        # Validate nonce length early to avoid backend ambiguity
        if len(nonce) != ChaChaCipher.nonce_size:
            raise ValueError(f"Invalid nonce length: expected {ChaChaCipher.nonce_size} bytes")
        cipher = ChaCha20Poly1305(enc_key)
        out = cipher.encrypt(nonce, plain, header)
        blob = out
        parity = RS_PARITY_BYTES if rs_use and len(blob) > RS_PARITY_BYTES else 0
        if parity:
            blob = rs_encode_data(blob, parity)
        payload = nonce + struct.pack(">I", len(blob)) + blob
        return idx, payload

    @staticmethod
    def decode_chunk(
        idx: int,
        cipher_blob: bytes,
        nonce: bytes,
        enc_key: bytes,
        rs_use: bool,
        header: bytes = b"",
    ) -> tuple[int, bytes]:
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
                core = orig_blob[:-parity] if attempt == "strip_parity" else blob
                if len(core) < TAG_LEN:
                    last_err = ValueError("Chunk too small for tag")
                    continue
                ct, tag = core[:-TAG_LEN], core[-TAG_LEN:]
                cipher = ChaCha20Poly1305(enc_key)
                plain = _dec(cipher, ct, tag, nonce, header)
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


class XChaChaCipher(BaseCipher):
    alg_tag = b"XC20"
    hkdf_info = b"PFA-keys"
    nonce_size = 24
    use_global_hmac = True
    supports_rs = True

    @staticmethod
    def encode_chunk(
        idx: int,
        plain: bytes,
        nonce: bytes,
        enc_key: bytes,
        rs_use: bool,
        header: bytes = b"",
    ) -> tuple[int, bytes]:
        if ChaCha20_Poly1305 is None:
            raise RuntimeError("PyCryptodome não encontrado – XChaCha indisponível.")
        # Validate nonce length early (XChaCha expects 24 bytes)
        if len(nonce) != XChaChaCipher.nonce_size:
            raise ValueError(f"Invalid nonce length: expected {XChaChaCipher.nonce_size} bytes")
        cipher = ChaCha20_Poly1305.new(key=enc_key, nonce=nonce)
        cipher.update(header)  # aplica AAD corretamente
        ct = cipher.encrypt(plain)
        tag = cipher.digest()
        blob = ct + tag
        parity = RS_PARITY_BYTES if rs_use and len(blob) > RS_PARITY_BYTES else 0
        if parity:
            blob = rs_encode_data(blob, parity)
        payload = nonce + struct.pack(">I", len(blob)) + blob
        return idx, payload

    @staticmethod
    def decode_chunk(
        idx: int,
        cipher_blob: bytes,
        nonce: bytes,
        enc_key: bytes,
        rs_use: bool,
        header: bytes = b"",
    ) -> tuple[int, bytes]:
        if ChaCha20_Poly1305 is None:
            raise RuntimeError("PyCryptodome não encontrado – XChaCha indisponível.")
        blob = cipher_blob
        parity = RS_PARITY_BYTES if rs_use and len(blob) > RS_PARITY_BYTES else 0
        orig_blob = blob  # keep original buffer (with parity) for fallback
        if parity:
            try:
                blob = rs_decode_data(blob)  # decoded payload (without parity)
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
                core = orig_blob[:-parity] if attempt == "strip_parity" else blob
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
        logger.error(
            "Tag verification failed (idx=%d, len=%d) after %s attempts",
            idx,
            len(orig_blob),
            len(attempts),
        )
        raise last_err


def _dec(cipher, ct: bytes, tag: bytes, nonce: bytes, aad: bytes) -> bytes:
    """
    Descriptografa de forma compatível com:
      • cryptography.ChaCha20Poly1305 (método decrypt, 3 args)
      • PyCryptodome ChaCha20_Poly1305 (método decrypt_and_verify, 2 args + update)
    """
    if hasattr(cipher, "decrypt_and_verify"):  # PyCryptodome
        cipher.update(aad)
        return cipher.decrypt_and_verify(ct, tag)
    else:  # cryptography (ChaCha20Poly1305)
        return cipher.decrypt(nonce, ct + tag, aad)


__all__ = [
    "ChaChaCipher",
    "XChaChaCipher",
]
