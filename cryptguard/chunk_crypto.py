# chunk_crypto.py
"""
Encrypt/decrypt data in chunks using ChaCha20Poly1305, with optional
Reed-Solomon error correction.
"""

import struct
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

import config
from rs_codec import rs_encode_data, rs_decode_data


def encrypt_chunk(chunk: bytes, key: bytearray,
                  aad: bytes, chunk_index: int) -> bytes:
    """
    Encrypts a single chunk using ChaCha20Poly1305.
    The nonce is derived from chunk_index (12 bytes, big-endian).
    AAD includes chunk_index as well.
    Returns the encrypted block, optionally encoded with Reed-Solomon.
    """
    cipher = ChaCha20Poly1305(bytes(key))
    nonce = chunk_index.to_bytes(12, byteorder='big')
    full_aad = aad + b"|chunk_index=%d" % chunk_index
    enc_chunk = cipher.encrypt(nonce, chunk, full_aad)
    checksum = hashlib.sha256(chunk).digest()
    raw_block = nonce + struct.pack('>I', len(enc_chunk)) + enc_chunk + checksum

    if config.USE_RS:
        rs_block = rs_encode_data(raw_block)
        block_len = struct.pack('>I', len(rs_block))
        return block_len + rs_block
    else:
        block_len = struct.pack('>I', len(raw_block))
        return block_len + raw_block


def decrypt_chunk(data: bytes, key: bytearray,
                  offset: int, aad: bytes,
                  chunk_index: int):
    """
    Decrypts a single chunk. Returns (plaintext, new_offset) or (None, offset) on failure.
    """
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

    # raw_block contém: nonce(12 bytes) + enc_len(4 bytes) + enc_chunk(...) + checksum(32 bytes)
    if len(raw_block) < 12 + 4 + 32:
        print("Corrupted raw_block (too short)!")
        return None, offset

    nonce = raw_block[:12]
    enc_len = struct.unpack('>I', raw_block[12:16])[0]
    start_enc = 16
    end_enc = 16 + enc_len
    if end_enc + 32 > len(raw_block):
        print("Corrupted raw_block (invalid enc_len)!")
        return None, offset

    ciphertext = raw_block[start_enc:end_enc]
    checksum_stored = raw_block[end_enc:end_enc + 32]

    cipher = ChaCha20Poly1305(bytes(key))
    full_aad = aad + b"|chunk_index=%d" % chunk_index

    try:
        plaintext = cipher.decrypt(nonce, ciphertext, full_aad)
    except InvalidTag:
        print("Chunk decryption failed (InvalidTag).")
        return None, offset

    if hashlib.sha256(plaintext).digest() != checksum_stored:
        print("Chunk checksum mismatch!")
        return None, offset

    return plaintext, offset
