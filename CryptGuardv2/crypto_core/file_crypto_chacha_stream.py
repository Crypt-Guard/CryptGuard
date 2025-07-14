"""
file_crypto_chacha_stream.py  –  ChaCha20-Poly1305 (streaming)
• Divide em chunks CHUNK_SIZE (8 MiB)
• HKDF sub-chaves
• RS opcional, HMAC, RateLimiter
• Usa chunk_crypto.encrypt_chunk / decrypt_chunk
"""

from __future__ import annotations
import os, secrets, time, queue, concurrent.futures, struct, hmac, hashlib
from pathlib import Path
from typing  import Callable, Optional

from cryptography.hazmat.primitives.kdf.hkdf  import HKDF
from cryptography.hazmat.primitives.hashes    import SHA256

from .config          import (
    SecurityProfile,
    USE_RS,
    RS_PARITY_BYTES,
    CHUNK_SIZE,
    MAGIC,
    ENC_EXT,
    SIGN_METADATA,
    META_EXT
)
from .secure_bytes    import SecureBytes
from .kdf             import derive_key
from .key_obfuscator  import TimedExposure, KeyObfuscator
from .chunk_crypto    import encrypt_chunk, decrypt_chunk
from .metadata        import encrypt_meta_json, decrypt_meta_json
from .utils           import write_atomic_secure
from .logger          import logger
from .rate_limit      import check_allowed, register_failure, reset
from .rs_codec        import rs_encode_data, rs_decode_data

def _hkdf(master:SecureBytes):
    k = HKDF(algorithm=SHA256(), length=64, salt=None, info=b"PFA-keys").derive(master.to_bytes())
    return k[:32], k[32:]

# ---- ENCRYPT ----------------------------------------------------------------------
def encrypt_file(src_path:str|os.PathLike, password:str,
                 profile:SecurityProfile=SecurityProfile.BALANCED,
                 progress_cb:Optional[Callable[[int],None]]=None) -> str:

    src = Path(src_path); size = src.stat().st_size
    salt = secrets.token_bytes(16)
    master_obf = derive_key(SecureBytes(password.encode()), salt, profile)
    with TimedExposure(master_obf) as m: enc_key, hmac_key = _hkdf(m)
    enc_obf = KeyObfuscator(SecureBytes(enc_key)); enc_obf.obfuscate()

    rs_use = USE_RS and RS_PARITY_BYTES>0
    pq, futures = queue.PriorityQueue(), []
    with src.open("rb") as fin, concurrent.futures.ThreadPoolExecutor() as ex:
        idx = 0
        while (chunk := fin.read(CHUNK_SIZE)):
            nonce = secrets.token_bytes(12)
            fut = ex.submit(encrypt_chunk, idx, chunk, nonce, enc_obf, rs_use, RS_PARITY_BYTES)
            futures.append(fut); idx += 1
        for fut in concurrent.futures.as_completed(futures): pq.put(fut.result())

    out = bytearray(); out += salt + MAGIC + b"CHS3"
    while not pq.empty():
        _, payload = pq.get(); out += payload
        if progress_cb: progress_cb(len(out))

    dest = src.with_suffix(src.suffix + ENC_EXT)
    write_atomic_secure(dest, bytes(out))

    hmac_hex = hmac.new(hmac_key, out, hashlib.sha256).hexdigest() if SIGN_METADATA else None
    meta = dict(alg="CHS", profile=profile.name, use_rs=rs_use,
                rs_bytes=RS_PARITY_BYTES if rs_use else 0, hmac=hmac_hex,
                chunk=CHUNK_SIZE, size=size, ts=int(time.time()))
    encrypt_meta_json(dest.with_suffix(dest.suffix+META_EXT), meta, SecureBytes(password.encode()))

    enc_obf.clear(); master_obf.clear()
    logger.info("ChaCha-stream enc %s (%.1f MiB)", src.name, size/1048576)
    return str(dest)

# ---- DECRYPT ----------------------------------------------------------------------
def decrypt_file(enc_path:str|os.PathLike, password:str,
                 profile_hint:SecurityProfile=SecurityProfile.BALANCED,
                 progress_cb:Optional[Callable[[int],None]]=None) -> str:

    if not check_allowed(enc_path):
        raise RuntimeError("Aguarde antes de novas tentativas.")

    src = Path(enc_path)
    with src.open("rb") as fin:
        salt = fin.read(16); magic, tag = fin.read(4), fin.read(4)
        if magic!=MAGIC or tag!=b"CHS3": raise ValueError("Formato inválido.")

        master_obf = derive_key(SecureBytes(password.encode()), salt, profile_hint)
        with TimedExposure(master_obf) as m: enc_key, hmac_key = _hkdf(m)
        enc_obf = KeyObfuscator(SecureBytes(enc_key)); enc_obf.obfuscate()

        meta = decrypt_meta_json(src.with_suffix(src.suffix+META_EXT), SecureBytes(password.encode()))
        rs_use = meta["use_rs"]

        pq, futures = queue.PriorityQueue(), []
        ex = concurrent.futures.ThreadPoolExecutor()
        idx = 0
        while (hdr := fin.read(12+4)):
            nonce = hdr[:12]; (clen,) = struct.unpack("<I", hdr[12:16])
            cipher = fin.read(clen)
            futures.append(ex.submit(decrypt_chunk, idx, nonce, cipher, enc_obf, rs_use))
            idx += 1
        for fut in concurrent.futures.as_completed(futures): pq.put(fut.result())

    dest = src.with_name(src.stem)
    with dest.open("wb") as fout:
        while not pq.empty():
            _, chunk = pq.get(); fout.write(chunk)

    if SIGN_METADATA and meta["hmac"]:
        calc = hmac.new(hmac_key, src.read_bytes(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calc, meta["hmac"]):
            register_failure(enc_path)
            raise ValueError("Falha na verificação HMAC.")
    reset(enc_path)

    enc_obf.clear(); master_obf.clear()
    logger.info("ChaCha-stream dec %s", dest.name)
    return str(dest)
