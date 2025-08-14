"""
Reed–Solomon com cabeçalho autodescritivo de 2 bytes (parity length).
"""

from reedsolo import ReedSolomonError, RSCodec


def rs_encode_data(data: bytes, parity_bytes: int) -> bytes:
    if parity_bytes == 0:
        return b"\x00\x00" + data
    rsc = RSCodec(parity_bytes)
    enc = rsc.encode(data)
    return parity_bytes.to_bytes(2, "big") + enc


def rs_decode_data(blob: bytes) -> bytes:
    parity = int.from_bytes(blob[:2], "big")
    payload = blob[2:]
    if parity == 0:
        return payload
    try:
        return RSCodec(parity).decode(payload)[0]
    except ReedSolomonError as e:
        raise ValueError("Falha na correção Reed-Solomon.") from e
