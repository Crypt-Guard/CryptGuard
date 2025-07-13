"""
Funções para cifrar / decifrar um *chunk* ChaCha20-Poly1305
com AAD fixo “chunk_index”.
"""
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from .key_obfuscator import TimedExposure
from .rs_codec       import rs_encode_data, rs_decode_data

def _aad(idx: int) -> bytes:
    return f"|chunk_index={idx}".encode()

def encrypt_chunk(idx: int, chunk: bytes, nonce: bytes,
                  obf, use_rs: bool, parity: int):
    with TimedExposure(obf):
        cipher = ChaCha20Poly1305(obf.deobfuscate().to_bytes())
        ct = cipher.encrypt(nonce, chunk, _aad(idx))
    if use_rs:
        ct = rs_encode_data(ct, parity)
    return idx, nonce + struct.pack("<I", len(ct)) + ct

def decrypt_chunk(idx: int, nonce: bytes, cipher: bytes,
                  obf, use_rs: bool):
    if use_rs:
        cipher = rs_decode_data(cipher)
    with TimedExposure(obf):
        plain = ChaCha20Poly1305(obf.deobfuscate().to_bytes()).decrypt(
            nonce, cipher, _aad(idx)
        )
    return idx, plain
