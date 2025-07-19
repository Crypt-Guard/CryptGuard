"""
file_crypto_ctr.py  –  AES-256-CTR + HMAC-SHA256

Why CTR?
• very fast stream-cipher mode (hardware AES-NI)            (#1)
• easier to parallelise than CBC, keeps block size = 16 B
Security notes:
• nonce (iv) must NEVER repeat – we use 128-bit random iv.
• integrity is provided by global HMAC (encrypt-then-MAC).

This backend re-uses Argon2id → HKDF derivation identical
to file_crypto.py.  RS is optional; default = OFF.
"""
from __future__ import annotations
import os, time, hmac, hashlib, struct, secrets
from pathlib import Path
from typing  import Callable, Optional

from cryptography.hazmat.primitives.ciphers         import Cipher, algorithms, modes
from cryptography.hazmat.backends                   import default_backend

from .config          import *
from .secure_bytes    import SecureBytes
from .kdf             import derive_key
from .key_obfuscator  import TimedExposure
from .metadata        import encrypt_meta_json, decrypt_meta_json
from .utils           import (
    generate_unique_filename, write_atomic_secure,
    pack_enc_zip, unpack_enc_zip,
)
from .logger          import logger
from .rate_limit      import check_allowed, register_failure, reset
from .hkdf_utils import derive_keys as _hkdf      # só isso vem do hkdf_utils
from .kdf        import derive_key                # Argon2‑derive_key continua aqui

# ─── helpers ────────────────────────────────────────────────────────────
def _aes_ctr(enc_key: bytes, iv: bytes):
    return Cipher(algorithms.AES(enc_key), modes.CTR(iv),
                  backend=default_backend()).encryptor()

# ─── ENCRYPT ────────────────────────────────────────────────────────────
def encrypt_file(
    src_path: str | os.PathLike,
    password: str,
    profile: SecurityProfile = SecurityProfile.BALANCED,
    progress_cb: Optional[Callable[[int], None]] = None,
) -> str:
    src   = Path(src_path)
    size  = src.stat().st_size
    salt  = secrets.token_bytes(16)

    master_obf = derive_key(SecureBytes(password.encode()), salt, profile)
    with TimedExposure(master_obf) as master:
        enc_key, hmac_key = _hkdf(master, info=b"CGv2-keys", salt=salt)

    iv = secrets.token_bytes(16)
    enc  = _aes_ctr(enc_key, iv)
    h    = hmac.new(hmac_key, digestmod=hashlib.sha256)

    # build and MAC the header to prevent IV tampering
    header = salt + MAGIC + b"ACTR" + iv     # header (40 B)
    out = bytearray()
    out += header
    h.update(header)

    processed = 0

    with src.open("rb") as fin:
        while chunk := fin.read(CHUNK_SIZE):
            ct = enc.update(chunk)
            out += struct.pack("<I", len(ct)) + ct
            h.update(ct)
            processed += len(chunk)
            if progress_cb:
                progress_cb(processed)

    out += h.digest()
    enc_path = src.with_suffix(src.suffix + ENC_EXT)
    write_atomic_secure(enc_path, bytes(out))

    meta = dict(alg="AESCTR", profile=profile.name, size=size,
                ts=int(time.time()), iv=iv.hex())
    encrypt_meta_json(enc_path.with_suffix(enc_path.suffix + META_EXT),
                      meta, SecureBytes(password.encode()))

    zip_path = pack_enc_zip(enc_path)          # 👉 empacota .enc + .meta em ZIP
    master_obf.clear()
    logger.info("AES-CTR enc %s (%.1f MiB)", src.name, size/1048576)
    return str(zip_path)

# ─── DECRYPT ────────────────────────────────────────────────────────────
def decrypt_file(
    enc_path: str | os.PathLike,
    password: str,
    profile_hint: SecurityProfile = SecurityProfile.BALANCED,
    progress_cb: Optional[Callable[[int], None]] = None,
) -> str:
    if not check_allowed(enc_path):
        raise RuntimeError("Please wait before another attempt (rate limiter).")

    # Permite .zip ou .enc puro
    if str(enc_path).lower().endswith(".zip"):
        src, _tmp = unpack_enc_zip(Path(enc_path))
    else:
        src, _tmp = Path(enc_path), None
    # ------------------------------------------------------------------
    data = src.read_bytes()
    salt, magic, tag_alg, iv = data[:16], data[16:20], data[20:24], data[24:40]
    if magic != MAGIC or tag_alg != b"ACTR":
        raise ValueError("Unknown format.")
    pos = 40

    master_obf = derive_key(SecureBytes(password.encode()), salt, profile_hint)
    with TimedExposure(master_obf) as master:
        enc_key, hmac_key = _hkdf(master, info=b"CGv2-keys", salt=salt)
    dec = _aes_ctr(enc_key, iv)
    h   = hmac.new(hmac_key, digestmod=hashlib.sha256)
    # include header in HMAC so IV/magic/salt are authenticated
    h.update(data[:pos])

    meta = decrypt_meta_json(src.with_suffix(src.suffix + META_EXT),
                             SecureBytes(password.encode()))
    total_plain = meta["size"]

    plain, processed = bytearray(), 0
    while pos < len(data) - 32:          # last 32 B = HMAC
        (clen,) = struct.unpack("<I", data[pos:pos+4]); pos += 4
        ct      = data[pos:pos+clen];     pos += clen
        h.update(ct)
        dec_chunk = dec.update(ct)
        plain += dec_chunk
        processed += len(dec_chunk)
        if progress_cb:
            progress_cb(processed)

    if not hmac.compare_digest(h.digest(), data[-32:]):
        register_failure(enc_path)
        raise ValueError("HMAC mismatch – wrong password or corrupted file.")

    # if HMAC ok, replace old dest logic:
    orig_name = src.name[:-len(ENC_EXT)]          # remove only ".enc"
    stem, ext = os.path.splitext(orig_name)       # e.g. ("foo", ".png")
    parent = Path(enc_path).parent
    dest   = parent / f"{stem}_{secrets.token_hex(4)}{ext}"
    write_atomic_secure(dest, bytes(plain))

    reset(enc_path)
    master_obf.clear()
    logger.info("AES-CTR dec %s", dest.name)
    return str(dest)
    write_atomic_secure(dest, bytes(plain))

    reset(enc_path)
    master_obf.clear()
    logger.info("AES-CTR dec %s", dest.name)
    return str(dest)
