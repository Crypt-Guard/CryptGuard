# chunk_crypto.py

import struct
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from rs_codec import rs_encode_data, rs_decode_data
import config

def encrypt_chunk(chunk: bytes, key: bytearray, aad: bytes, chunk_index: int) -> bytes:
    """
    Encrypts a single chunk using ChaCha20Poly1305.
    The nonce is deterministically generated from the chunk index (12 bytes, big-endian).
    AAD is set as (aad + b"|chunk_index=xxx").
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

def decrypt_chunk(data: bytes, key: bytearray, offset: int, aad: bytes, chunk_index: int):
    """
    Decrypts a single chunk. Returns (plaintext, new_offset) or (None, offset) on failure.
    """
    if offset + 4 > len(data):
        return None, offset
    block_len = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    if offset + block_len > len(data):
        return None, offset

    block_data = data[offset:offset+block_len]
    offset += block_len

    if config.USE_RS:
        try:
            raw_block = rs_decode_data(block_data)
        except Exception:
            print("RS decoding error!")
            return None, offset
    else:
        raw_block = block_data

    nonce = raw_block[:12]
    enc_len = struct.unpack('>I', raw_block[12:16])[0]
    ciphertext = raw_block[16:16+enc_len]
    checksum_stored = raw_block[16+enc_len:16+enc_len+32]

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
