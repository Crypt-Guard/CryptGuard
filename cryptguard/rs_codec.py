# rs_codec.py

import struct
from reedsolo import RSCodec

# Inicializa Reed-Solomon com 32 bytes de paridade
rs = RSCodec(32)

def rs_encode_data(data: bytes, block_size=223) -> bytes:
    """
    Divide 'data' em blocos <= block_size e aplica Reed-Solomon.
    Retorna header + blocos codificados.
    """
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    encoded_blocks = [rs.encode(block) for block in blocks]
    header = struct.pack('>I', len(encoded_blocks))
    for block in encoded_blocks:
        header += struct.pack('>H', len(block))
    return header + b''.join(encoded_blocks)


def rs_decode_data(data: bytes) -> bytes:
    """
    Decodifica o que foi gerado por rs_encode_data.
    """
    if len(data) < 4:
        raise ValueError("Dados RS incompletos.")
    num_blocks = struct.unpack('>I', data[:4])[0]
    offset = 4
    block_lengths = []
    for _ in range(num_blocks):
        if offset + 2 > len(data):
            raise ValueError("Header RS incompleto.")
        length = struct.unpack('>H', data[offset:offset+2])[0]
        block_lengths.append(length)
        offset += 2
    decoded = b""
    for length in block_lengths:
        block = data[offset:offset+length]
        offset += length
        decoded += rs.decode(block)[0]
    return decoded
