"""
file_crypto_chacha.py  –  ChaCha20-Poly1305 (single-shot)
• HKDF sub-chaves
• Sub-chunks de 1 MiB com re-ofuscação
• RS opcional + HMAC global
• RateLimiter
"""

from __future__ import annotations
import math, os, struct, secrets, hmac, hashlib, time, mmap, tempfile, shutil
from pathlib import Path
from typing  import Callable, Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .config         import *
from .secure_bytes   import SecureBytes
from .kdf            import derive_key
from .key_obfuscator import TimedExposure
from .rs_codec       import rs_encode_data, rs_decode_data
from .metadata       import encrypt_meta_json, decrypt_meta_json
from .utils          import write_atomic_secure, pack_enc_zip, unpack_enc_zip
from .logger         import logger
from .rate_limit     import check_allowed, register_failure, reset

from .hkdf_utils import derive_keys as _hkdf      # só isso vem do hkdf_utils
from .kdf        import derive_key                # Argon2‑derive_key continua aqui


# ---- helpers ----------------------------------------------------------------------
def _enc_block(chunk:bytes, nonce:bytes, enc_key:bytes, rs_use:bool)->bytes:
    ct = ChaCha20Poly1305(enc_key).encrypt(nonce, chunk, None)
    if rs_use: ct = rs_encode_data(ct, RS_PARITY_BYTES)
    return nonce + struct.pack("<I", len(ct)) + ct

def _dec_block(nonce:bytes, ct:bytes, enc_key:bytes, rs_use:bool)->bytes:
    if rs_use: ct = rs_decode_data(ct)
    return ChaCha20Poly1305(enc_key).decrypt(nonce, ct, None)

# ---- ENCRYPT ----------------------------------------------------------------------
def encrypt_file(src_path: str, password, profile=SecurityProfile.BALANCED,
                 progress_cb:Optional[Callable[[int],None]]=None) -> str:

    pwd_sb = password if isinstance(password, SecureBytes) else SecureBytes(password.encode())

    src = Path(src_path)
    
    # Use mmap for memory-efficient file reading
    with open(src, "rb") as f_src, \
         mmap.mmap(f_src.fileno(), 0, access=mmap.ACCESS_READ) as data:
        
        size = len(data)
        salt = secrets.token_bytes(16)
        master_obf = derive_key(pwd_sb, salt, profile)

        with TimedExposure(master_obf) as m:
            enc_key, hmac_key = _hkdf(m, info=b"PFA-keys", salt=salt)
        rs_use = USE_RS and RS_PARITY_BYTES>0
        n_sub  = math.ceil(size / SINGLE_SHOT_SUBCHUNK_SIZE)
        out    = bytearray()
        out += salt + MAGIC + b"CH20" + struct.pack("<I", n_sub)

        processed = 0
        for i in range(n_sub):
            chunk = data[i*SINGLE_SHOT_SUBCHUNK_SIZE : (i+1)*SINGLE_SHOT_SUBCHUNK_SIZE]
            nonce = secrets.token_bytes(12)
            out += _enc_block(chunk, nonce, enc_key, rs_use)
            processed += len(chunk)
            if progress_cb: progress_cb(processed)

    enc_path = src.with_suffix(src.suffix + ENC_EXT)
    write_atomic_secure(enc_path, bytes(out))

    hmac_hex = (hmac.new(hmac_key, enc_path.read_bytes(), hashlib.sha256)
                .hexdigest() if SIGN_METADATA else None)
    meta = dict(alg="CHACHA", profile=profile.name, use_rs=rs_use,
                rs_bytes=RS_PARITY_BYTES if rs_use else 0, hmac=hmac_hex,
                subchunk=SINGLE_SHOT_SUBCHUNK_SIZE, size=size, ts=int(time.time()))
    encrypt_meta_json(enc_path.with_suffix(enc_path.suffix + META_EXT),
                      meta, pwd_sb)

    zip_path = pack_enc_zip(enc_path)

    pwd_sb.clear()
    logger.info("ChaCha enc %s (%d KiB)", src.name, size>>10)
    return str(zip_path)

# ---- DECRYPT ----------------------------------------------------------------------
def decrypt_file(enc_path:str|os.PathLike, password:str,
                 profile_hint:SecurityProfile=SecurityProfile.BALANCED,
                 progress_cb:Optional[Callable[[int],None]]=None) -> str:

    if not check_allowed(enc_path):
        raise RuntimeError("Limite de tentativas excedido – aguarde.")

    # suporta .zip
    if str(enc_path).lower().endswith(".zip"):
        src, _tmp = unpack_enc_zip(Path(enc_path))
    else:
        src, _tmp = Path(enc_path), None
    
    # Use mmap for memory-efficient file reading
    with open(src, "rb") as f_src, \
         mmap.mmap(f_src.fileno(), 0, access=mmap.ACCESS_READ) as blob:
        
        salt, magic, tag_alg = blob[:16], blob[16:20], blob[20:24]
        if magic!=MAGIC or tag_alg!=b"CH20": raise ValueError("Formato inválido.")

        n_sub, = struct.unpack("<I", blob[24:28])
        master_obf = derive_key(SecureBytes(password.encode()), salt, profile_hint)
        with TimedExposure(master_obf) as m:
            enc_key, hmac_key = _hkdf(m, info=b"PFA-keys", salt=salt)

        meta = decrypt_meta_json(src.with_suffix(src.suffix+META_EXT), SecureBytes(password.encode()))
        rs_use = meta["use_rs"]

        pos = 28; plain = bytearray(); processed = 0
        for _ in range(n_sub):
            nonce = blob[pos:pos+12]; pos+=12
            (clen,) = struct.unpack("<I", blob[pos:pos+4]); pos+=4
            ct  = blob[pos:pos+clen]; pos+=clen
            chunk = _dec_block(nonce, ct, enc_key, rs_use)
            plain += chunk
            processed += len(chunk)
            if progress_cb: progress_cb(processed)

    parent = Path(enc_path).parent
    orig   = src.name[:-len(ENC_EXT)]
    dest   = parent / orig
    if dest.exists():
        from .utils import generate_unique_filename
        dest = generate_unique_filename(dest)
    write_atomic_secure(dest, bytes(plain))

    if SIGN_METADATA and meta["hmac"]:
        # Re-read file for HMAC verification using mmap
        with open(src, "rb") as f_hmac, \
             mmap.mmap(f_hmac.fileno(), 0, access=mmap.ACCESS_READ) as hmac_data:
            calc = hmac.new(hmac_key, hmac_data, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(calc, meta["hmac"]):
                register_failure(enc_path)
                raise ValueError("Falha na verificação HMAC.")
    reset(enc_path)

    master_obf.clear()
    logger.info("ChaCha dec %s", dest.name)
    return str(dest)
    master_obf.clear()
    logger.info("ChaCha dec %s", dest.name)
    return str(dest)
