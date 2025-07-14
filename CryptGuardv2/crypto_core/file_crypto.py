"""
file_crypto.py  –  AES-256-GCM (streaming) v3

• KDF: Argon2id  ➜ HKDF-SHA256 → enc_key ‖ hmac_key
• Reed-Solomon opcional (config.USE_RS / RS_PARITY_BYTES)
• HMAC-SHA256 global
• Metadata JSON duplamente cifrado
• RateLimiter exponencial por arquivo
"""

from __future__ import annotations
import os, time, hmac, hashlib, struct, secrets, queue, concurrent.futures
from pathlib import Path
from typing  import Callable, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf     import HKDF
from cryptography.hazmat.primitives.hashes       import SHA256
from cryptography.exceptions import InvalidTag

from .config          import *
from .secure_bytes    import SecureBytes
from .key_obfuscator  import TimedExposure
from .kdf             import derive_key
from .rs_codec        import rs_encode_data, rs_decode_data
from .metadata        import encrypt_meta_json, decrypt_meta_json
from .utils           import write_atomic_secure, generate_unique_filename
from .logger          import logger
from .rate_limit      import check_allowed, register_failure, reset
from .security_warning import warn

# ───────────────────────────────────────── helpers ────────────────────────────────
def _optimal_workers(sz:int) -> int:
    return 4 if sz < 100*2**20 else 8 if sz < 2**30 else 12

def _hkdf(master:SecureBytes) -> tuple[bytes, bytes]:
    """Deriva (enc_key, hmac_key) de 32 bytes cada."""
    k = HKDF(algorithm=SHA256(), length=64, salt=None, info=b"PFA-keys").derive(master.to_bytes())
    return k[:32], k[32:]          # 64 = 32 + 32

def _enc_chunk(i:int, data:bytes, nonce:bytes, enc_key:bytes) -> tuple[int, bytes]:
    ct = AESGCM(enc_key).encrypt(nonce, data, None)
    tag, cipher = ct[-16:], ct[:-16]
    return i, nonce + tag + struct.pack("<I", len(cipher)) + cipher

def _dec_chunk(i:int, hdr:bytes, cipher:bytes, enc_key:bytes) -> tuple[int, bytes]:
    nonce, tag = hdr[:12], hdr[12:28]
    try:
        plain = AESGCM(enc_key).decrypt(nonce, cipher + tag, None)
    except InvalidTag as e:
        raise ValueError("Senha incorreta ou arquivo corrompido.") from e
    return i, plain

# ───────────────────────────────────────── ENCRYPT ───────────────────────────────
def encrypt_file(src_path:str|os.PathLike, password:str,
                 profile:SecurityProfile=SecurityProfile.BALANCED,
                 progress_cb:Optional[Callable[[int],None]]=None) -> str:

    src   = Path(src_path)
    size  = src.stat().st_size
    salt  = secrets.token_bytes(16)

    # Argon2id → KeyObfuscator com chave mestra
    master_obf = derive_key(SecureBytes(password.encode()), salt, profile)

    # HKDF → chaves finais
    with TimedExposure(master_obf) as master:
        enc_key, hmac_key = _hkdf(master)

    rs_use  = USE_RS and RS_PARITY_BYTES > 0
    pq      = queue.PriorityQueue()
    workers = _optimal_workers(size)
    processed = 0
    start = time.time()

    with src.open("rb", buffering=CHUNK_SIZE*4) as fin, \
         concurrent.futures.ThreadPoolExecutor(workers) as ex:

        futures, idx = [], 0
        while (chunk := fin.read(CHUNK_SIZE)):
            nonce = secrets.token_bytes(12)
            futures.append(ex.submit(_enc_chunk, idx, chunk, nonce, enc_key))
            idx += 1

        for fut in concurrent.futures.as_completed(futures):
            i, payload = fut.result()
            if rs_use:
                # ------- reparar comprimento -------
                nonce    = payload[:12]
                tag      = payload[12:28]
                # skip past (12 nonce + 16 tag + 4 old length)
                cipher   = payload[32:]
                cipher_rs = rs_encode_data(cipher, RS_PARITY_BYTES)

                new_len  = struct.pack("<I", len(cipher_rs))
                payload  = nonce + tag + new_len + cipher_rs
            pq.put((i, payload))

    out_path = src.with_suffix(src.suffix + ENC_EXT)
    with out_path.open("wb") as fout:
        fout.write(salt + MAGIC + b"AESG")
        while not pq.empty():
            _, pl = pq.get()
            fout.write(pl)
            processed += len(pl) - (12+16+4)
            if progress_cb: progress_cb(processed)

    # HMAC global
    hmac_hex = None
    if SIGN_METADATA:
        hmac_hex = hmac.new(hmac_key, out_path.read_bytes(), hashlib.sha256).hexdigest()

    # Metadata
    meta = dict(alg="AESGCM", profile=profile.name, use_rs=rs_use,
                rs_bytes=RS_PARITY_BYTES if rs_use else 0, hmac=hmac_hex,
                chunk=CHUNK_SIZE, size=size, ts=int(start))
    encrypt_meta_json(out_path.with_suffix(out_path.suffix + META_EXT),
                      meta, SecureBytes(password.encode()))

    logger.info("AES enc %s (%.1f MiB)", src.name, size/1048576)
    master_obf.clear()
    return str(out_path)

# ───────────────────────────────────────── DECRYPT ───────────────────────────────
def decrypt_file(enc_path:str|os.PathLike, password:str,
                 profile_hint:SecurityProfile=SecurityProfile.BALANCED,
                 progress_cb:Optional[Callable[[int],None]]=None) -> str:

    if not check_allowed(enc_path):
        raise RuntimeError("Muitas tentativas falhas; aguarde antes de tentar novamente.")

    src = Path(enc_path)
    with src.open("rb", buffering=CHUNK_SIZE*4) as fin:
        salt = fin.read(16)
        magic, tag_alg = fin.read(4), fin.read(4)
        if magic != MAGIC or tag_alg != b"AESG":
            raise ValueError("Formato de arquivo desconhecido.")

        master_obf = derive_key(SecureBytes(password.encode()), salt, profile_hint)
        with TimedExposure(master_obf) as master:
            enc_key, hmac_key = _hkdf(master)

        meta = decrypt_meta_json(src.with_suffix(src.suffix + META_EXT),
                                 SecureBytes(password.encode()))
        rs_use = meta["use_rs"]

        futures, pq = [], queue.PriorityQueue()
        ex = concurrent.futures.ThreadPoolExecutor(_optimal_workers(meta["size"]))
        idx = 0; header = 12+16+4
        while (hdr := fin.read(header)):
            (clen,) = struct.unpack("<I", hdr[28:32])
            cipher  = fin.read(clen)
            if rs_use:
                cipher = rs_decode_data(cipher)
            futures.append(ex.submit(_dec_chunk, idx, hdr[:28], cipher, enc_key))
            idx += 1

        for fut in concurrent.futures.as_completed(futures):
            pq.put(fut.result())

    orig_name = src.name[:-len(ENC_EXT)]                    # strip only ".enc"
    stem, ext = os.path.splitext(orig_name)                 # split name + original ext
    dest = src.with_name(f"{stem}_{secrets.token_hex(4)}{ext}")
    processed = 0
    with dest.open("wb") as fout:
        while not pq.empty():
            _, chunk = pq.get()
            fout.write(chunk)
            processed += len(chunk)
            if progress_cb: progress_cb(processed)

    # HMAC verify
    if SIGN_METADATA and meta["hmac"]:
        calc = hmac.new(hmac_key, src.read_bytes(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(calc, meta["hmac"]):
            register_failure(enc_path)
            raise ValueError("Falha HMAC – arquivo ou senha incorretos.")
    reset(enc_path)

    master_obf.clear()
    logger.info("AES dec %s", dest.name)
    return str(dest)
