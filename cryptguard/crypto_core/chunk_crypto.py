# crypto_core/chunk_crypto.py
"""
Encrypt/decrypt data in chunks using ChaCha20Poly1305, with optional
Reed-Solomon error correction.

[CORREÇÃO IMPORTANTE]
- Removemos o hash do plaintext (checksum SHA-256) que estava em claro,
  pois o AEAD já garante integridade/autenticidade.
- O formato agora: nonce(12 bytes) + enc_len(4 bytes) + enc_chunk(...).
- Isso quebra compatibilidade com versões anteriores que usavam checksum.
"""

import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from crypto_core import config
from crypto_core.rs_codec import rs_encode_data, rs_decode_data
from crypto_core.secure_bytes import SecureBytes

def encrypt_chunk(chunk: bytes, key, aad: bytes, chunk_index: int) -> bytes:
    if isinstance(key, SecureBytes):
        cipher = ChaCha20Poly1305(memoryview(key.to_bytes()))
    else:
        cipher = ChaCha20Poly1305(key)
        
    nonce = chunk_index.to_bytes(12, byteorder='big')
    full_aad = aad + b"|chunk_index=%d" % chunk_index
    enc_chunk = cipher.encrypt(nonce, chunk, full_aad)

    raw_block = nonce + struct.pack('>I', len(enc_chunk)) + enc_chunk

    if config.USE_RS:
        rs_block = rs_encode_data(raw_block)
        block_len = struct.pack('>I', len(rs_block))
        return block_len + rs_block
    else:
        block_len = struct.pack('>I', len(raw_block))
        return block_len + raw_block


def decrypt_chunk(data: bytes, key,
                  offset: int, aad: bytes,
                  chunk_index: int):
    if offset + 4 > len(data):
        return None, offset
    block_len = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4

    if offset + block_len > len(data):
        return None, offset

    block_data = data[offset:offset + block_len]
    offset += block_len

    if config.USE_RS:
        try:
            raw_block = rs_decode_data(block_data)
        except Exception:
            print("RS decoding error!")
            return None, offset
    else:
        raw_block = block_data

    if len(raw_block) < 12 + 4:
        print("Corrupted raw_block (too short)!")
        return None, offset

    nonce = raw_block[:12]
    enc_len = struct.unpack('>I', raw_block[12:16])[0]
    start_enc = 16
    end_enc = 16 + enc_len
    if end_enc > len(raw_block):
        print("Corrupted raw_block (invalid enc_len)!")
        return None, offset

    ciphertext = raw_block[start_enc:end_enc]
    
    if isinstance(key, SecureBytes):
        cipher = ChaCha20Poly1305(memoryview(key.to_bytes()))
    else:
        cipher = ChaCha20Poly1305(key)
        
    full_aad = aad + b"|chunk_index=%d" % chunk_index

    try:
        plaintext = cipher.decrypt(nonce, ciphertext, full_aad)
    except InvalidTag:
        print("Chunk decryption failed (InvalidTag).")
        return None, offset

    return plaintext, offset
