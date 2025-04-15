# crypto_core/rs_codec.py
"""
Reed-Solomon encoding/decoding for error correction.
"""

import struct
from reedsolo import RSCodec
from crypto_core.config import RS_PARITY_BYTES

def rs_encode_data(data: bytes, block_size: int = 223, parity_bytes: int = RS_PARITY_BYTES) -> bytes:
    rs = RSCodec(parity_bytes)
    blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    encoded_blocks = [rs.encode(block) for block in blocks]
    header = struct.pack('>I', len(encoded_blocks))
    for block in encoded_blocks:
        header += struct.pack('>H', len(block))
    return header + b''.join(encoded_blocks)

def rs_decode_data(data: bytes, parity_bytes: int = RS_PARITY_BYTES) -> bytes:
    if len(data) < 4:
        raise ValueError("Incomplete RS data.")
    num_blocks = struct.unpack('>I', data[:4])[0]
    offset = 4
    block_lengths = []
    for _ in range(num_blocks):
        if offset + 2 > len(data):
            raise ValueError("Incomplete RS header.")
        length = struct.unpack('>H', data[offset:offset + 2])[0]
        block_lengths.append(length)
        offset += 2
    decoded = b""
    rs = RSCodec(parity_bytes)
    for length in block_lengths:
        block = data[offset:offset + length]
        if len(block) < length:
            raise ValueError("Incomplete RS block data.")
        offset += length
        try:
            decoded_block = rs.decode(block)[0]
        except Exception as e:
            raise ValueError(f"RS decode failed: {e}")
        decoded += decoded_block
    return decoded
