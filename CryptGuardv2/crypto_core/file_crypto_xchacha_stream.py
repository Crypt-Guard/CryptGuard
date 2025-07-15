"""
file_crypto_xchacha_stream.py – XChaCha20‑Poly1305 (streaming)
• Divide em chunks CHUNK_SIZE (8 MiB por padrão)
• HKDF sub‑chaves, RS opcional, HMAC global, RateLimiter
• Mesma lógica do file_crypto_chacha_stream.py, mas:
    – nonce = 24 bytes (XChaCha)
    – PyCryptodome ChaCha20_Poly1305
"""

from __future__ import annotations
import os, secrets, time, queue, struct, hmac, hashlib, concurrent.futures
from pathlib import Path
from typing  import Callable, Optional

from Crypto.Cipher import ChaCha20_Poly1305          # suporta 24 B nonce
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes    import SHA256

from .config         import (
    SecurityProfile, USE_RS, RS_PARITY_BYTES, CHUNK_SIZE, MAGIC,
    ENC_EXT, SIGN_METADATA, META_EXT, STREAMING_THRESHOLD
)
from .secure_bytes   import SecureBytes
from .kdf            import derive_key
from .key_obfuscator import TimedExposure, KeyObfuscator
from .rs_codec       import rs_encode_data, rs_decode_data
from .metadata       import encrypt_meta_json, decrypt_meta_json
from .utils          import write_atomic_secure, pack_enc_zip, unpack_enc_zip
from .logger         import logger
from .rate_limit     import check_allowed, register_failure, reset

_NONCE = 24                      # XChaCha20‑Poly1305

# ───────────────────────── helpers ─────────────────────────
def _hkdf(master: SecureBytes):
    k = HKDF(algorithm=SHA256(), length=64, salt=None,
             info=b"PFA-keys").derive(master.to_bytes())
    return k[:32], k[32:]        # enc_key, hmac_key

def _aad(idx: int) -> bytes:
    return f"|chunk={idx}".encode()

def _enc_chunk(idx: int, chunk: bytes, nonce: bytes,
               obf: KeyObfuscator, use_rs: bool) -> tuple[int, bytes]:
    # Encripta um chunk e devolve (idx, payload) ordenável.
    with TimedExposure(obf):
        key = obf.deobfuscate().to_bytes()
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(_aad(idx))
    ct, tag = cipher.encrypt_and_digest(chunk)
    payload = ct + tag
    if use_rs:
        payload = rs_encode_data(payload, RS_PARITY_BYTES)
    return idx, nonce + struct.pack("<I", len(payload)) + payload

def _dec_chunk(idx: int, nonce: bytes, cipher_blob: bytes,
               obf: KeyObfuscator, use_rs: bool) -> tuple[int, bytes]:
    if use_rs:
        cipher_blob = rs_decode_data(cipher_blob)
    ct, tag = cipher_blob[:-16], cipher_blob[-16:]
    with TimedExposure(obf):
        key = obf.deobfuscate().to_bytes()
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(_aad(idx))
    plain = cipher.decrypt_and_verify(ct, tag)
    return idx, plain

# ───────────────────────── ENCRYPT ─────────────────────────
def encrypt_file(src_path: str | os.PathLike, password: str,
                 profile: SecurityProfile = SecurityProfile.BALANCED,
                 progress_cb: Optional[Callable[[int], None]] = None) -> str:

    src   = Path(src_path)
    size  = src.stat().st_size
    salt  = secrets.token_bytes(16)

    pwd_sb = (password if isinstance(password, SecureBytes)
              else SecureBytes(password.encode()))
    master = derive_key(pwd_sb, salt, profile)
    with TimedExposure(master) as m:
        enc_key, hmac_key = _hkdf(m)
    enc_obf = KeyObfuscator(SecureBytes(enc_key)); enc_obf.obfuscate()

    rs_use = USE_RS and RS_PARITY_BYTES > 0
    pq, futures = queue.PriorityQueue(), []
    processed = 0                           # NOVO
    total_chunks = 0
    
    with src.open("rb") as fin, concurrent.futures.ThreadPoolExecutor() as ex:
        idx = 0
        while (chunk := fin.read(CHUNK_SIZE)):
            nonce = secrets.token_bytes(_NONCE)
            fut = ex.submit(_enc_chunk, idx, chunk, nonce, enc_obf, rs_use)
            futures.append(fut); idx += 1
        total_chunks = idx
        
        # Process futures with exception handling
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
            enc_obf.clear(); master.clear(); pwd_sb.clear()
            raise errors[0]

    # Verify all chunks were processed
    if pq.qsize() != total_chunks:
        enc_obf.clear(); master.clear(); pwd_sb.clear()
        raise RuntimeError(f"Chunk count mismatch: expected {total_chunks}, got {pq.qsize()}")

    out = bytearray(salt + MAGIC + b"XCS3")                # header para stream XChaCha
    while not pq.empty():
        _, payload = pq.get()
        out += payload

    # Use temporary file during write
    dest = src.with_suffix(src.suffix + ENC_EXT)
    dest_temp = dest.with_suffix(dest.suffix + ".part")
    
    try:
        write_atomic_secure(dest_temp, bytes(out))
        dest_temp.rename(dest)              # cria foo.enc

        hmac_hex = (hmac.new(hmac_key, dest.read_bytes(), hashlib.sha256)
                    .hexdigest() if SIGN_METADATA else None)
        meta = dict(alg="XCHACHA_STREAM", profile=profile.name, use_rs=rs_use,
                    rs_bytes=RS_PARITY_BYTES if rs_use else 0,
                    chunk=CHUNK_SIZE, size=size, hmac=hmac_hex,
                    ts=int(time.time()))
        encrypt_meta_json(dest.with_suffix(dest.suffix + META_EXT),
                          meta, pwd_sb)     # grava foo.enc.meta

        dest = pack_enc_zip(dest)           # agora inclui .enc + .enc.meta
    except Exception as e:
        dest_temp.unlink(missing_ok=True)
        enc_obf.clear(); master.clear(); pwd_sb.clear()
        raise e

    hmac_hex = (hmac.new(hmac_key, dest.read_bytes(), hashlib.sha256)
                .hexdigest() if SIGN_METADATA else None)
    meta = dict(alg="XCHACHA_STREAM", profile=profile.name, use_rs=rs_use,
                rs_bytes=RS_PARITY_BYTES if rs_use else 0,
                chunk=CHUNK_SIZE, size=size, hmac=hmac_hex,
                ts=int(time.time()))
    encrypt_meta_json(dest.with_suffix(dest.suffix + META_EXT),
                      meta, pwd_sb)
    pwd_sb.clear()
    logger.info("XChaCha‑stream enc %s (%.1f MiB)",
                src.name, size/1048576)
    return str(dest)

# ───────────────────────── DECRYPT ─────────────────────────
def decrypt_file(enc_path: str | os.PathLike, password: str,
                 profile_hint: SecurityProfile = SecurityProfile.BALANCED,
                 progress_cb: Optional[Callable[[int], None]] = None) -> str:

    if not check_allowed(enc_path):
        raise RuntimeError("Aguarde antes de novas tentativas.")

    if str(enc_path).lower().endswith(".zip"):
        src, _tmp = unpack_enc_zip(Path(enc_path))
    else:
        src, _tmp = Path(enc_path), None

    dest = src.with_name(src.stem)
    dest_temp = dest.with_suffix(dest.suffix + ".part")

    try:
        with src.open("rb") as fin:
            salt  = fin.read(16)
            magic = fin.read(4); tag = fin.read(4)
            if magic != MAGIC or tag != b"XCS3":
                raise ValueError("Formato inválido.")

            pwd_sb = (password if isinstance(password, SecureBytes)
                      else SecureBytes(password.encode()))
            master = derive_key(pwd_sb, salt, profile_hint)
            with TimedExposure(master) as m:
                enc_key, hmac_key = _hkdf(m)
            enc_obf = KeyObfuscator(SecureBytes(enc_key)); enc_obf.obfuscate()

            meta   = decrypt_meta_json(src.with_suffix(src.suffix + META_EXT),
                                       SecureBytes(password.encode()))
            rs_use = meta["use_rs"]

            pq, futures = queue.PriorityQueue(), []
            processed = 0                           # NOVO
            ex = concurrent.futures.ThreadPoolExecutor()
            total_chunks = 0
            
            try:
                idx = 0
                while (hdr := fin.read(_NONCE + 4)):
                    if len(hdr) < (_NONCE + 4):
                        break
                    nonce = hdr[:_NONCE]
                    (clen,) = struct.unpack("<I", hdr[_NONCE:_NONCE+4])
                    cipher_blob = fin.read(clen)
                    futures.append(ex.submit(_dec_chunk, idx, nonce,
                                             cipher_blob, enc_obf, rs_use))
                    idx += 1
                total_chunks = idx
                
                # Process futures with exception handling
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
                
                if errors:
                    raise errors[0]
                    
            finally:
                ex.shutdown(wait=False)

        # Verify all chunks were processed
        if pq.qsize() != total_chunks:
            raise RuntimeError(f"Chunk count mismatch: expected {total_chunks}, got {pq.qsize()}")

        with dest_temp.open("wb") as fout:
            while not pq.empty():
                _, chunk = pq.get()
                fout.write(chunk)

        if SIGN_METADATA and meta["hmac"]:
            calc = hmac.new(hmac_key, src.read_bytes(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(calc, meta["hmac"]):
                register_failure(enc_path)
                raise ValueError("Falha na verificação HMAC.")
        
        # Move temp file to final destination
        dest_temp.rename(dest)
        reset(enc_path)

    except Exception as e:
        # Cleanup partial file on any error
        dest_temp.unlink(missing_ok=True)
        if 'enc_obf' in locals():
            enc_obf.clear()
        if 'master' in locals():
            master.clear()
        raise e

    enc_obf.clear(); master.clear()
    logger.info("XChaCha‑stream dec %s", dest.name)
    return str(dest)
