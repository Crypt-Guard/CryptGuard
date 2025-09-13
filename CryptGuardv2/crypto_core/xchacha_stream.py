from __future__ import annotations

import hmac
import json
import os
import struct
from pathlib import Path
from typing import Optional
from hashlib import blake2b

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .fileformat_v5 import (
    SS_HEADER_BYTES,
    V5Header,
    canonical_json_bytes,
    read_v5_header,
)
from .kdf_v5 import derive_key_from_params_json, derive_key_v5
try:  # optional best-effort secure memory
    from .securemem import secret_bytes as _secret_bytes
except Exception:  # pragma: no cover - optional
    _secret_bytes = None

# ---- SecretStream bindings and compatibility wrappers ----------------------
try:
    from nacl.bindings import crypto_secretstream as ssb
except Exception as _e:  # pragma: no cover - environment dependent
    ssb = None


def _load_secretstream_bindings():
    if ssb is None:
        raise _MissingSecretStream(
            "PyNaCl/libsodium nÃ£o disponÃ­vel para SecretStream. Instale com: pip install pynacl"
        )
    # sanity check against file format constant
    if ssb.crypto_secretstream_xchacha20poly1305_HEADERBYTES != SS_HEADER_BYTES:
        raise RuntimeError("libsodium header size mismatch")

    # expose aliases used in this module
    return {
        "ss_init_push": ssb.crypto_secretstream_xchacha20poly1305_init_push,
        "ss_init_pull": ssb.crypto_secretstream_xchacha20poly1305_init_pull,
        "ss_push": ssb.crypto_secretstream_xchacha20poly1305_push,
        "ss_pull": ssb.crypto_secretstream_xchacha20poly1305_pull,
        "ss_state": ssb.crypto_secretstream_xchacha20poly1305_state,
        "TAG_MESSAGE": ssb.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
        "TAG_FINAL": ssb.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    }


_SS = _load_secretstream_bindings()
ss_init_push = _SS["ss_init_push"]
ss_init_pull = _SS["ss_init_pull"]
ss_push = _SS["ss_push"]
ss_pull = _SS["ss_pull"]
ss_state = _SS["ss_state"]
TAG_MESSAGE = _SS["TAG_MESSAGE"]
TAG_FINAL = _SS["TAG_FINAL"]


def ss_init_push_compat(key: bytes):
    """Normalize PyNaCl SecretStream init_push variants to return (state, header).

    Tries:
      - init_push(key) -> (state, header)
      - init_push(state, key) -> header
    """
    try:
        state, header = ss_init_push(key)  # convenience API
        return state, header
    except TypeError:
        state = ss_state()
        header = ss_init_push(state, key)  # C-like: returns header
        return state, header


def ss_init_pull_compat(header: bytes, key: bytes):
    """Normalize PyNaCl SecretStream init_pull variants to return state.

    Tries:
      - init_pull(header, key) -> state
      - init_pull(state, header, key) -> None (returns None and fills state)
    """
    try:
        return ss_init_pull(header, key)
    except TypeError:
        state = ss_state()
        ss_init_pull(state, header, key)
        return state


class _MissingSecretStream(RuntimeError):
    pass


def _require_secretstream():
    try:
        from nacl.bindings import (
            crypto_secretstream_xchacha20poly1305_init_push,
            crypto_secretstream_xchacha20poly1305_init_pull,
            crypto_secretstream_xchacha20poly1305_push,
            crypto_secretstream_xchacha20poly1305_pull,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
            crypto_secretstream_xchacha20poly1305_TAG_FINAL,
            crypto_secretstream_xchacha20poly1305_HEADERBYTES,
            crypto_secretstream_xchacha20poly1305_STATEBYTES,
            crypto_secretstream_xchacha20poly1305_state as SS_STATE_CLS,
        )
        # sanity
        if crypto_secretstream_xchacha20poly1305_HEADERBYTES != SS_HEADER_BYTES:
            raise RuntimeError("libsodium header size mismatch")
        return (
            crypto_secretstream_xchacha20poly1305_init_push,
            crypto_secretstream_xchacha20poly1305_init_pull,
            crypto_secretstream_xchacha20poly1305_push,
            crypto_secretstream_xchacha20poly1305_pull,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
            crypto_secretstream_xchacha20poly1305_TAG_FINAL,
            crypto_secretstream_xchacha20poly1305_STATEBYTES,
            SS_STATE_CLS,
        )
    except Exception as e:  # pragma: no cover - environment dependent
        raise _MissingSecretStream(
            "PyNaCl/libsodium nÃ£o disponÃ­vel para SecretStream. Instale com: pip install pynacl"
        ) from e


def _coerce_pwd(password: str | bytes) -> bytes:
    return password.encode() if isinstance(password, str) else password


def _pad_chunk(data: bytes, policy: str) -> bytes:
    if policy == "off":
        return data
    if policy not in ("4k", "16k"):
        raise ValueError("padding must be 'off', '4k' or '16k'")
    block = 4096 if policy == "4k" else 16384
    rem = len(data) % block
    if rem == 0:
        return data
    return data + b"\x00" * (block - rem)


def _u32(n: int) -> bytes:
    return struct.pack(">I", n)


def _read_exact(f, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = f.read(n - len(buf))
        if not chunk:
            raise ValueError("Truncated stream")
        buf += chunk
    return buf


class XChaChaStream:
    """Encrypt/decrypt CG2 v5 using libsodium SecretStream.

    Note: This implementation frames messages with a 4-byte big-endian length
    prefix per ciphertext message for robust I/O. All header bytes are bound
    as AAD on every push/pull.
    """

    def encrypt_file(
        self,
        in_path: str | os.PathLike,
        password: str | bytes,
        *,
        out_path: str | os.PathLike | None = None,
        kdf_profile: str = "INTERACTIVE",
        padding: str = "off",
        keyfile: str | os.PathLike | None = None,
        hide_filename: bool = False,
    ) -> str:
        pwd = _coerce_pwd(password)
        in_p = Path(in_path)
        out_p = Path(out_path) if out_path else Path(in_path).with_suffix(".cg2")

        key32, kdf_json = derive_key_v5(pwd, kdf_profile)
        # Optional keyfile mixing (2FA)
        if keyfile:
            kb = Path(keyfile).read_bytes()
            kpep = blake2b(b"CG3-KFILE" + kb, digest_size=32).digest()
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"CG3\x00kfile-mix", info=b"key-derivation/v3")
            key32 = hkdf.derive(key32 + kpep)
            kb = None
        
        # InicializaÃ§Ã£o compatÃ­vel do SecretStream
        if _secret_bytes is not None:
            with _secret_bytes(initial=key32) as _kmv:
                state, ss_header = ss_init_push_compat(bytes(_kmv))
        else:
            _key_ba = bytearray(key32)
            state, ss_header = ss_init_push_compat(bytes(_key_ba))
            for i in range(len(_key_ba)):
                _key_ba[i] = 0
        
        header = V5Header(kdf_params_json=kdf_json, ss_header=ss_header).pack()

        # Basic metadata to finalize inside the stream
        total_pt = 0
        chunks = 0

        out_p.parent.mkdir(parents=True, exist_ok=True)
        with in_p.open("rb") as fin, out_p.open("wb") as fout:
            fout.write(header)

            # Stream chunks with optional padding
            while True:
                chunk = fin.read(1024 * 1024)  # 1 MiB read window
                if not chunk:
                    break
                total_pt += len(chunk)
                chunk = _pad_chunk(chunk, padding)
                ct = ss_push(state, chunk, header, TAG_MESSAGE)
                fout.write(_u32(len(ct)))
                fout.write(ct)
                chunks += 1

            # Final metadata inside TAG_FINAL
                meta = {
                "chunks": int(chunks),
                "pt_size": int(total_pt),
                "orig_ext": Path(in_p.name).suffix or "",
                "orig_name": None if hide_filename else Path(in_p.name).name,
                "padding": padding,
            }
            meta_blob = canonical_json_bytes(meta)
            final_ct = ss_push(state, meta_blob, header, TAG_FINAL)
            fout.write(_u32(len(final_ct)))
            fout.write(final_ct)

        return str(out_p.resolve())

    def decrypt_file(
        self,
        in_path: str | os.PathLike,
        password: str | bytes,
        *,
        out_path: str | os.PathLike | None = None,
        verify_only: bool = False,
        keyfile: str | os.PathLike | None = None,
    ) -> Optional[str]:
        pwd = _coerce_pwd(password)
        src = Path(in_path)
        dst = Path(out_path) if out_path else Path(str(src.with_suffix("")))
        dst_dir = dst.parent

        # Parse header and bind as AAD
        hdr, header_bytes, off = read_v5_header(src)
        key32 = derive_key_from_params_json(pwd, hdr.kdf_params_json)
        if keyfile:
            kb = Path(keyfile).read_bytes()
            kpep = blake2b(b"CG3-KFILE" + kb, digest_size=32).digest()
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"CG3\x00kfile-mix", info=b"key-derivation/v3")
            key32 = hkdf.derive(key32 + kpep)
            kb = None

        # InicializaÃ§Ã£o compatÃ­vel do lado de leitura
        if _secret_bytes is not None:
            with _secret_bytes(initial=key32) as _kmv:
                state = ss_init_pull_compat(hdr.ss_header, bytes(_kmv))
        else:
            _key_ba = bytearray(key32)
            state = ss_init_pull_compat(hdr.ss_header, bytes(_key_ba))
            for i in range(len(_key_ba)):
                _key_ba[i] = 0

        # Read framed messages: [len|4][ciphertext] ... until TAG_FINAL
        from .securetemp import SecureTempFile
        with src.open("rb") as f:
            f.seek(off)
            final_seen = False
            out = None
            tmp = None
            final_meta = {}
            try:
                if not verify_only:
                    tmp = SecureTempFile(suffix=".part", dir=str(dst_dir))
                    out = tmp.fh
                while True:
                    ln_bytes = f.read(4)
                    if not ln_bytes:
                        break
                    if len(ln_bytes) < 4:
                        raise ValueError("Falha na autenticaÃ§Ã£o")
                    (clen,) = struct.unpack(">I", ln_bytes)
                    if clen <= 0 or clen > (1 << 31):
                        raise ValueError("Falha na autenticaÃ§Ã£o")
                    c = _read_exact(f, clen)
                    try:
                        ret = ss_pull(state, c, header_bytes)
                    except Exception:
                        raise ValueError("Falha na autentica??uo")
                    ad = b""
                    if isinstance(ret, tuple) and len(ret) == 2:
                        pt, tag = ret
                    elif isinstance(ret, tuple) and len(ret) == 3:
                        pt, ad, tag = ret
                    else:
                        raise ValueError("Falha na autentica??uo")
                    # tag is a small int; constant-time compare to FINAL
                    if hmac.compare_digest(bytes([tag]), bytes([TAG_FINAL])):
                        # finalize
                        # finalize: metadata may be in pt or ad (JSON). Avoid writing JSON to output.
                        meta_bytes = ad if ad else pt
                        if meta_bytes:
                            try:
                                final_meta = json.loads(meta_bytes)
                            except Exception:
                                # Not valid JSON; write only if it's actual data (no AAD present)
                                if not verify_only and out is not None and pt and not ad:
                                    out.write(pt)
                        final_seen = True
                        # ensure no trailing bytes after final
                        rest = f.read(1)
                        if rest:
                            raise ValueError("Falha na autenticaÃ§Ã£o")
                        break
                    else:
                        if verify_only:
                            continue
                        if out is None:
                            raise ValueError("Falha na autenticaÃ§Ã£o")
                        out.write(pt)
            finally:
                if out is not None:
                    try:
                        out.flush()
                    except Exception:
                        pass
                # tmp is closed/finalized later

            if not final_seen:
                raise ValueError("Falha na autenticaÃ§Ã£o")

        if verify_only:
            return None

        # Decide final filename using metadata
        final_dst = dst
        if isinstance(final_meta, dict):
            orig_name = final_meta.get("orig_name")
            orig_ext = final_meta.get("orig_ext")
        else:
            orig_name = None
            orig_ext = None

        # If user didn't supply out_path, prefer original filename; otherwise, handle hidden-filename mode
        if out_path is None and orig_name:
            final_dst = dst.parent / orig_name
        elif out_path is None and (not orig_name) and orig_ext:
            final_dst = dst.parent / f"decrypted{orig_ext}"
        elif (out_path is not None) and (not final_dst.suffix) and orig_ext:
            final_dst = final_dst.with_suffix(orig_ext)

        # Avoid overwriting existing files
        if final_dst.exists():
            stem, suf = final_dst.stem, final_dst.suffix
            i = 1
            while True:
                cand = final_dst.with_name(f"{stem}({i}){suf}")
                if not cand.exists():
                    final_dst = cand
                    break
                i += 1

        # Finalize temp into place atomically
        if tmp is not None:
            try:
                tmp.finalize(final_dst)
            finally:
                tmp = None
        return str(final_dst.resolve())


__all__ = [
    "XChaChaStream",
]
