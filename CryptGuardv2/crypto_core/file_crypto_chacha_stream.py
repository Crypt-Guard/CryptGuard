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

from .hkdf_utils import derive_keys as _hkdf

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
from crypto_core.secure_bytes import SecureBytes
from .kdf             import derive_key
from .key_obfuscator  import TimedExposure, KeyObfuscator
from .chunk_crypto    import encrypt_chunk, decrypt_chunk
from .metadata        import encrypt_meta_json, decrypt_meta_json
from .utils           import write_atomic_secure, pack_enc_zip, unpack_enc_zip
from .logger          import logger
from .rate_limit      import check_allowed, register_failure, reset
from .hkdf_utils import derive_keys as _hkdf      # só isso vem do hkdf_utils
from .kdf        import derive_key                # Argon2‑derive_key continua aqui

# ---- ENCRYPT ----------------------------------------------------------------------
def encrypt_file(src_path:str|os.PathLike, password:str,
                 profile:SecurityProfile=SecurityProfile.BALANCED,
                 progress_cb:Optional[Callable[[int],None]]=None) -> str:

    src = Path(src_path); size = src.stat().st_size
    salt = secrets.token_bytes(16)
    pwd_sb = password if isinstance(password, SecureBytes) else SecureBytes(password.encode())
    master_obf = derive_key(pwd_sb, salt, profile)
    with TimedExposure(master_obf) as m:
        enc_key, hmac_key = _hkdf(m, info=b"PFA-keys", salt=salt)
    enc_obf = KeyObfuscator(SecureBytes(enc_key)); enc_obf.obfuscate()

    rs_use = USE_RS and RS_PARITY_BYTES>0
    pq, futures = queue.PriorityQueue(), []
    processed = 0                           # NOVO
    
    with src.open("rb") as fin, concurrent.futures.ThreadPoolExecutor() as ex:
        idx = 0
        while (chunk := fin.read(CHUNK_SIZE)):
            nonce = secrets.token_bytes(12)
            fut = ex.submit(encrypt_chunk, idx, chunk, nonce, enc_obf, rs_use, RS_PARITY_BYTES)
            futures.append(fut); idx += 1
        
        total_chunks = idx
        errors = []
        
        for fut in concurrent.futures.as_completed(futures):
            exc = fut.exception()
            if exc:
                errors.append(exc)
                # Cancel remaining futures
                for f in futures:
                    f.cancel()
                break
            else:
                idx2, payload = fut.result()
                pq.put((idx2, payload))
                processed += len(payload)              # bytes prontos
                if progress_cb:
                    # Garante que nunca passa de 100 %
                    progress_cb(min(processed, size))
        
        if errors:
            enc_obf.clear(); master_obf.clear()
            raise errors[0]

    # Validate chunk count
    if pq.qsize() != total_chunks:
        enc_obf.clear(); master_obf.clear()
        raise RuntimeError(f"Chunks processados ({pq.qsize()}) != esperados ({total_chunks})")

    out = bytearray(salt + MAGIC + b"CHS3")
    while not pq.empty():
        _, payload = pq.get()
        out += payload

    enc_path = src.with_suffix(src.suffix + ENC_EXT)
    temp_path = enc_path.with_suffix(enc_path.suffix + ".part")
    
    try:
        write_atomic_secure(temp_path, bytes(out))
        
        hmac_hex = (hmac.new(hmac_key, temp_path.read_bytes(), hashlib.sha256)
                    .hexdigest() if SIGN_METADATA else None)
        meta = dict(alg="CHS", profile=profile.name, use_rs=rs_use,
                    rs_bytes=RS_PARITY_BYTES if rs_use else 0, hmac=hmac_hex,
                    chunk=CHUNK_SIZE, size=size, ts=int(time.time()))
        encrypt_meta_json(temp_path.with_suffix(temp_path.suffix+META_EXT),
                          meta, pwd_sb)
        
        # Rename to final path only after everything succeeds
        os.replace(temp_path, enc_path)
        meta_temp = temp_path.with_suffix(temp_path.suffix+META_EXT)
        meta_temp.rename(enc_path.with_suffix(enc_path.suffix+META_EXT))
        
        zip_path = pack_enc_zip(enc_path)
        
    except Exception as e:
        # Cleanup partial files
        temp_path.unlink(missing_ok=True)
        temp_path.with_suffix(temp_path.suffix+META_EXT).unlink(missing_ok=True)
        enc_obf.clear(); master_obf.clear()
        raise e

    enc_obf.clear(); master_obf.clear()
    logger.info("ChaCha-stream enc %s (%.1f MiB)", src.name, size/1048576)
    return str(zip_path)

# ---- DECRYPT ----------------------------------------------------------------------
def decrypt_file(enc_path:str|os.PathLike, password:str,
                 profile_hint:SecurityProfile=SecurityProfile.BALANCED,
                 progress_cb:Optional[Callable[[int],None]]=None) -> str:

    if not check_allowed(enc_path):
        raise RuntimeError("Aguarde antes de novas tentativas.")

    if str(enc_path).lower().endswith(".zip"):
        src, _tmp = unpack_enc_zip(Path(enc_path))
    else:
        src, _tmp = Path(enc_path), None

    with src.open("rb") as fin:
        salt = fin.read(16); magic, tag = fin.read(4), fin.read(4)
        if magic!=MAGIC or tag!=b"CHS3": raise ValueError("Formato inválido.")

        pwd_sb = password if isinstance(password, SecureBytes) else SecureBytes(password.encode())
        master_obf = derive_key(pwd_sb, salt, profile_hint)
        with TimedExposure(master_obf) as m:
            enc_key, hmac_key = _hkdf(m, info=b"PFA-keys", salt=salt)
        enc_obf = KeyObfuscator(SecureBytes(enc_key)); enc_obf.obfuscate()

        meta = decrypt_meta_json(src.with_suffix(src.suffix+META_EXT), SecureBytes(password.encode()))
        rs_use = meta["use_rs"]

        pq, futures = queue.PriorityQueue(), []
        processed = 0                           # NOVO
        ex = concurrent.futures.ThreadPoolExecutor()
        idx = 0
        while (hdr := fin.read(12+4)):
            nonce = hdr[:12]; (clen,) = struct.unpack("<I", hdr[12:16])
            cipher = fin.read(clen)
            futures.append(ex.submit(decrypt_chunk, idx, nonce, cipher, enc_obf, rs_use))
            idx += 1
        
        total_chunks = idx
        errors = []
        
        for fut in concurrent.futures.as_completed(futures):
            exc = fut.exception()
            if exc:
                errors.append(exc)
                # Cancel remaining futures
                for f in futures:
                    f.cancel()
                break
            else:
                idx2, chunk = fut.result()
                pq.put((idx2, chunk))
                processed += len(chunk)              # bytes prontos
                if progress_cb:
                    # Garante que nunca passa de 100 %
                    progress_cb(min(processed, meta["size"]))
        
        ex.shutdown(wait=False)
        
        if errors:
            enc_obf.clear(); master_obf.clear()
            register_failure(enc_path)
            raise errors[0]

    # Validate chunk count
    if pq.qsize() != total_chunks:
        enc_obf.clear(); master_obf.clear()
        raise RuntimeError(f"Chunks processados ({pq.qsize()}) != esperados ({total_chunks})")

    dest = src.with_name(src.stem)
    temp_dest = dest.with_suffix(dest.suffix + ".part")
    
    try:
        with temp_dest.open("wb") as fout:
            while not pq.empty():
                _, chunk = pq.get()
                fout.write(chunk)

        if SIGN_METADATA and meta["hmac"]:
            calc = hmac.new(hmac_key, src.read_bytes(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(calc, meta["hmac"]):
                temp_dest.unlink(missing_ok=True)
                register_failure(enc_path)
                raise ValueError("Falha na verificação HMAC.")
        
        # Rename to final path only after everything succeeds
        os.replace(temp_dest, dest)
        
    except Exception as e:
        # Cleanup partial files
        temp_dest.unlink(missing_ok=True)
        enc_obf.clear(); master_obf.clear()
        raise e

    reset(enc_path)

    enc_obf.clear(); master_obf.clear()
    logger.info("ChaCha-stream dec %s", dest.name)
    return str(dest)
    enc_obf.clear(); master_obf.clear()
    logger.info("ChaCha-stream dec %s", dest.name)
    return str(dest)
