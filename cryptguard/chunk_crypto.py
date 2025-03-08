# chunk_crypto.py

import struct
import hashlib
# Removido a importação de secrets para nonce aleatório – usaremos o índice
import secrets  
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from rs_codec import rs_encode_data, rs_decode_data

def encrypt_chunk(chunk: bytes, key: bytearray, aad: bytes, chunk_index: int) -> bytes:
    """
    Criptografa 1 chunk com ChaCha20Poly1305.
    O nonce é gerado de forma determinística a partir do índice do chunk,
    convertendo o índice para 12 bytes (big-endian).
    AAD = (aad + b"|chunk_index=xxx").
    Retorna bloco já codificado em Reed-Solomon.
    """
    cipher = ChaCha20Poly1305(bytes(key))
    # Gera nonce determinístico: chunk_index em 12 bytes
    nonce = chunk_index.to_bytes(12, byteorder='big')
    full_aad = aad + b"|chunk_index=%d" % chunk_index
    enc_chunk = cipher.encrypt(nonce, chunk, full_aad)
    checksum = hashlib.sha256(chunk).digest()
    raw_block = nonce + struct.pack('>I', len(enc_chunk)) + enc_chunk + checksum
    rs_block = rs_encode_data(raw_block)
    block_len = struct.pack('>I', len(rs_block))
    return block_len + rs_block

def decrypt_chunk(data: bytes, key: bytearray, offset: int, aad: bytes, chunk_index: int):
    """
    Descriptografa 1 chunk. Retorna (plaintext, novo_offset) ou (None, offset).
    """
    if offset + 4 > len(data):
        return None, offset
    block_len = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    if offset + block_len > len(data):
        return None, offset

    rs_block = data[offset:offset+block_len]
    offset += block_len

    try:
        raw_block = rs_decode_data(rs_block)
    except Exception:
        print("Erro na decodificação RS!")
        return None, offset

    nonce = raw_block[:12]
    enc_len = struct.unpack('>I', raw_block[12:16])[0]
    ciphertext = raw_block[16:16+enc_len]
    checksum_stored = raw_block[16+enc_len:16+enc_len+32]

    cipher = ChaCha20Poly1305(bytes(key))
    full_aad = aad + b"|chunk_index=%d" % chunk_index

    try:
        plaintext = cipher.decrypt(nonce, ciphertext, full_aad)
    except InvalidTag:
        print("Falha na descriptografia de um chunk (InvalidTag).")
        return None, offset

    if hashlib.sha256(plaintext).digest() != checksum_stored:
        print("Checksum do chunk não confere!")
        return None, offset

    return plaintext, offset
