"""
Funções para cifrar / decifrar um *chunk* ChaCha20-Poly1305
com AAD fixo "chunk_index".
"""
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from .key_obfuscator import TimedExposure
from .rs_codec       import rs_encode_data, rs_decode_data

def _aad(idx: int) -> bytes:
    return f"|chunk_index={idx}".encode()

def encrypt_chunk(idx: int, chunk: bytes, nonce: bytes,
                  obf, use_rs: bool, parity: int, header_aad: bytes = b""):
    # Combina AAD do header com chunk index
    combined_aad = header_aad + _aad(idx)
    with TimedExposure(obf):
        cipher = ChaCha20Poly1305(obf.deobfuscate().to_bytes())
        ct = cipher.encrypt(nonce, chunk, combined_aad)
    if use_rs:
        ct = rs_encode_data(ct, parity)
    return idx, nonce + struct.pack("<I", len(ct)) + ct

def decrypt_chunk(idx: int, nonce: bytes, cipher: bytes,
                  obf, use_rs: bool, header_aad: bytes = b""):
    if use_rs:
        cipher = rs_decode_data(cipher)
    # Combina AAD do header com chunk index
    combined_aad = header_aad + _aad(idx)
    with TimedExposure(obf):
        plain = ChaCha20Poly1305(obf.deobfuscate().to_bytes()).decrypt(
            nonce, cipher, combined_aad
        )
    return idx, plain

def encrypt_file(fin, fout, key: bytes, backend, *, aad: bytes = b"", chunk_size: int = 1<<20):
    """
    Lê de fin, escreve em fout. Para cada chunk, usa 'aad' como AAD.
    """
    idx = 0
    while True:
        pt = fin.read(chunk_size)
        if not pt: 
            break
        nonce = backend.make_nonce(idx)   # ou o seu esquema atual
        ct = backend.encrypt_chunk(key, nonce, pt, aad)
        fout.write(ct)
        idx += 1

def decrypt_file(fin, fout, key: bytes, backend, *, aad: bytes = b"", chunk_size: int = 1<<20, verify_only: bool = False):
    idx = 0
    while True:
        ct = fin.read(chunk_size + 32)  # ajuste ao seu framing real
        if not ct: 
            break
        nonce = backend.make_nonce(idx)
        pt = backend.decrypt_chunk(key, nonce, ct, aad)  # se tag inválida → exception
        if not verify_only:
            fout.write(pt)
        idx += 1
