from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import struct
import time
import warnings
from hashlib import blake2b
from pathlib import Path
from typing import Any, Dict

from crypto_core.logger import logger

from .fileformat_v5 import (
    SS_HEADER_BYTES,
    V5Header,
    VERSION,
    canonical_json_bytes,
    read_v5_header,
)
from .hkdf_utils import derive_subkey
from .kdf import derive_key_from_params_json, derive_key_v5

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
            "PyNaCl/libsodium not available for SecretStream. Install with: pip install pynacl"
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


# --- Strict expiration (optional): corrupt the file when it expires -------------
# Controlled via environment variable (default: ON).
AUTO_CORRUPT_ON_EXPIRE = str(os.getenv("CG2_STRICT_EXPIRE", "1")).lower() not in (
    "0",
    "false",
    "no",
)


def _self_corrupt(path: Path) -> None:
    """Overwrite the start of the file to break the v5 header (irreversible for that copy)."""
    try:
        with open(path, "r+b", buffering=0) as f:
            f.seek(0)
            f.write(os.urandom(128))
            f.flush()
            os.fsync(f.fileno())
    except Exception as exc:
        logger.debug("Suppressed exception in xchacha_stream: %s", exc)


def _mix_with_keyfile(key32: bytes, keyfile_path: str | os.PathLike) -> bytes:
    """
    Mix the master key with a keyfile using HKDF-SHA256.
    Uses hkdf_utils.derive_subkey so we do not depend on cryptography.HKDF.
    """
    kb = Path(keyfile_path).read_bytes()
    kpep = blake2b(b"CG3-KFILE" + kb, digest_size=32).digest()
    return derive_subkey(key32, "key-derivation/v3", length=32, context={}, salt=kpep)


def _get_rate_limit_hooks():
    """
    Best-effort import of rate limiting helpers.
    Falls back to no-ops when optional modules are unavailable.
    """
    try:
        from .database import (
            check_password_attempts,
            record_failed_attempt,
            reset_failed_attempts,
        )

        return check_password_attempts, record_failed_attempt, reset_failed_attempts
    except Exception:
        warnings.warn(
            "Rate-limit database not available; proceeding without centralized rate limiting.",
            RuntimeWarning,
            stacklevel=2,
        )
        return (
            lambda *args, **kwargs: True,
            lambda *args, **kwargs: None,
            lambda *args, **kwargs: None,
        )


_log = logging.getLogger(__name__)


def _decode_kdf_json(kdf_json: bytes) -> Dict[str, Any]:
    try:
        return json.loads(kdf_json.decode("utf-8"))
    except Exception as exc:  # pragma: no cover - defensive, upstream should ensure canonical JSON
        raise ValueError("KDF JSON inválido") from exc


def _aad_bytes_from_obj(obj: Dict[str, Any]) -> bytes:
    return canonical_json_bytes(obj)


def _ensure_bytes_hex(hex_value: str, expected_len: int | None = None) -> bytes:
    data = bytes.fromhex(hex_value)
    if expected_len is not None and len(data) != expected_len:
        raise ValueError("Comprimento inesperado de dado em hex")
    return data


def _binding_payload_bytes(kdf_obj: Dict[str, Any]) -> bytes:
    payload = dict(kdf_obj)
    payload.pop("binding_mac_hex", None)
    return canonical_json_bytes(payload)


def extract_aad_bytes_from_params(kdf_params_json: bytes) -> bytes | None:
    """
    Helper exposto para testes/integrações: retorna os bytes do AAD canônico
    descrito no KDF JSON (se disponível), caso contrário `None`.
    """
    obj = _decode_kdf_json(kdf_params_json)
    ctx = obj.get("aad_context")
    if isinstance(ctx, dict):
        return _aad_bytes_from_obj(ctx)
    return None


@contextlib.contextmanager
def _redact_meta_logs(enabled: bool):
    """
    When enabled, redact any 'orig_name' occurrences from debug/info logs in this module.
    """
    if not enabled:
        yield
        return
    patt_json = re.compile(r'("orig_name"\s*:\s*")([^"]+)(")')
    patt_kv_s = re.compile(r"(orig_name\s*=\s*')([^']+)(')")
    patt_kv_d = re.compile(r'(orig_name\s*=\s*")([^"]+)(")')

    class _F(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            try:
                msg = record.getMessage()
                # redact orig_name JSON and key=value variants
                msg = patt_json.sub(r"\1[hidden]\3", msg)
                msg = patt_kv_s.sub(r"\1[hidden]\3", msg)
                msg = patt_kv_d.sub(r"\1[hidden]\3", msg)
                record.msg = msg
                record.args = ()
            except Exception as exc:
                logger.debug("Suppressed exception in xchacha_stream: %s", exc)
            return True

    f = _F()
    _log.addFilter(f)
    try:
        yield
    finally:
        _log.removeFilter(f)


class KeyfileRequiredError(PermissionError):
    """Raised when the file requires a keyfile and none was provided."""

    pass


class ExpiredCG2Error(PermissionError):
    """Raised when the file is expired."""

    pass


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
            crypto_secretstream_xchacha20poly1305_HEADERBYTES,
            crypto_secretstream_xchacha20poly1305_init_pull,
            crypto_secretstream_xchacha20poly1305_init_push,
            crypto_secretstream_xchacha20poly1305_pull,
            crypto_secretstream_xchacha20poly1305_push,
            crypto_secretstream_xchacha20poly1305_STATEBYTES,
            crypto_secretstream_xchacha20poly1305_TAG_FINAL,
            crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
        )
        from nacl.bindings import (
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
            "PyNaCl/libsodium not available for SecretStream. Install with: pip install pynacl"
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
    pad_len = block - rem if rem else block
    return data + b"\x00" * pad_len


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
        expires_at: int | None = None,
    ) -> str:
        pwd = _coerce_pwd(password)
        in_p = Path(in_path)
        out_p = Path(out_path) if out_path else Path(in_path).with_suffix(".cg2")

        key32, base_kdf_json = derive_key_v5(pwd, kdf_profile)
        kdf_obj = _decode_kdf_json(base_kdf_json)
        if expires_at is not None:
            try:
                kdf_obj["exp"] = int(expires_at)
            except Exception as exc:
                logger.debug("Suppressed exception in xchacha_stream: %s", exc)
        if keyfile:
            kdf_obj["kfile"] = True

        master_key = key32
        if keyfile:
            master_key = _mix_with_keyfile(master_key, keyfile)

        hkdf_salt = os.urandom(32)
        hkdf_salt_hex = hkdf_salt.hex()
        created_at = int(time.time())
        logical_name = Path(in_p.name).name
        aad_logical_path = "__hidden__" if hide_filename else logical_name
        aad_context: Dict[str, Any] = {
            "version": VERSION,
            "purpose": "file",
            "alg": "xchacha20-poly1305+secretstream",
            "kdf": {
                "algo": kdf_obj.get("algo", "argon2id"),
                "t": int(kdf_obj.get("t", 0)),
                "m": int(kdf_obj.get("m", 0)),
                "p": int(kdf_obj.get("p", 0)),
                "profile": kdf_obj.get("profile", "INTERACTIVE"),
            },
            "hkdf_salt_hex": hkdf_salt_hex,
            "logical_path": aad_logical_path,
            "created_at": created_at,
        }
        if expires_at is not None:
            aad_context["expires_at"] = int(expires_at)
        if keyfile:
            aad_context["keyfile"] = True
        if hide_filename:
            aad_context["hide_filename"] = True

        kdf_obj["hkdf_salt_hex"] = hkdf_salt_hex
        kdf_obj["aad_context"] = aad_context

        aad_bytes = _aad_bytes_from_obj(aad_context)
        enc_key = derive_subkey(master_key, "CryptGuard/v5 enc", context=aad_context, salt=hkdf_salt)
        bind_key = derive_subkey(master_key, "CryptGuard/v5 bind", context=aad_context, salt=hkdf_salt)

        if _secret_bytes is not None:
            with _secret_bytes(initial=enc_key) as _ekmv:
                state, ss_header = ss_init_push_compat(bytes(_ekmv))
        else:
            _enc_ba = bytearray(enc_key)
            state, ss_header = ss_init_push_compat(bytes(_enc_ba))
            for i in range(len(_enc_ba)):
                _enc_ba[i] = 0

        binding_payload = _binding_payload_bytes(kdf_obj)
        binding_mac = hmac.new(
            bind_key, binding_payload + ss_header, hashlib.sha256
        ).digest()
        kdf_obj["binding_mac_hex"] = binding_mac.hex()

        # Zeroizar chaves derivadas (melhor esforço) após uso direto
        try:
            _b = bytearray(enc_key)
            for i in range(len(_b)):
                _b[i] = 0
        except Exception:
            pass
        try:
            _b = bytearray(bind_key)
            for i in range(len(_b)):
                _b[i] = 0
        except Exception:
            pass

        kdf_json = canonical_json_bytes(kdf_obj)
        header_bytes = V5Header(kdf_params_json=kdf_json, ss_header=ss_header).pack()
        with _redact_meta_logs(hide_filename):
            _log.debug("v5 header ready; kdf_json_len=%d hide=%s", len(kdf_json), hide_filename)

        # Basic metadata to finalize inside the stream
        total_pt = 0
        chunks = 0

        out_p.parent.mkdir(parents=True, exist_ok=True)
        with in_p.open("rb") as fin, out_p.open("wb") as fout:
            fout.write(header_bytes)

            # Stream chunks with optional padding applied to the final chunk only
            read_size = 1024 * 1024  # 1 MiB read window
            chunk = fin.read(read_size)
            while chunk:
                next_chunk = fin.read(read_size)
                total_pt += len(chunk)
                policy = padding if not next_chunk else "off"
                chunk_to_encrypt = _pad_chunk(chunk, policy)
                ct = ss_push(state, chunk_to_encrypt, aad_bytes, TAG_MESSAGE)
                fout.write(_u32(len(ct)))
                fout.write(ct)
                chunks += 1
                chunk = next_chunk

            # Final metadata inside TAG_FINAL (after the loop)
            pad_value = padding if isinstance(padding, str) else "off"
            meta = {
                "chunks": int(chunks),
                "pt_size": int(total_pt),
                "orig_ext": Path(in_p.name).suffix or "",
                "padding": pad_value,
            }
            if not hide_filename:
                meta["orig_name"] = Path(in_p.name).name
            meta["created_at"] = created_at
            meta_blob = canonical_json_bytes(meta)
            final_ct = ss_push(state, meta_blob, aad_bytes, TAG_FINAL)
            fout.write(_u32(len(final_ct)))
            fout.write(final_ct)

        # best-effort: remover referAancia A  chave o quanto antes
        try:
            del key32
        except Exception as exc:
            logger.debug("Suppressed exception in xchacha_stream: %s", exc)
        return str(out_p.resolve())

    def decrypt_file(
        self,
        in_path: str | os.PathLike,
        password: str | bytes,
        *,
        out_path: str | os.PathLike | None = None,
        verify_only: bool = False,
        keyfile: str | os.PathLike | None = None,
    ) -> str | None:
        pwd = _coerce_pwd(password)
        src = Path(in_path)
        dst = Path(out_path) if out_path else Path(str(src.with_suffix("")))
        dst_dir = dst.parent

        check_password_attempts, record_failed_attempt, reset_failed_attempts = (
            _get_rate_limit_hooks()
        )
        src_identifier = str(src)

        if not check_password_attempts(src_identifier, max_attempts=3):
            raise RuntimeError("Too many failed attempts for this file; try again later.")

        try:
            # Parse header and bind as AAD
            hdr, header_bytes, off = read_v5_header(src)
            kdf_obj = _decode_kdf_json(hdr.kdf_params_json)
            # Fail-fast: expiration stored in the header (KDF_JSON) before streaming starts
            try:
                exp = kdf_obj.get("exp")
                if exp is not None and time.time() > int(exp):
                    if AUTO_CORRUPT_ON_EXPIRE:
                        _self_corrupt(src)
                    raise ExpiredCG2Error("File expired")
                # Fail clearly if the file requires a keyfile and none was provided
                if kdf_obj.get("kfile") is True and not keyfile:
                    raise KeyfileRequiredError("File requires keyfile")
            except (ExpiredCG2Error, KeyfileRequiredError):
                # Propagate intentional authorization errors; they are part of the contract
                raise
            except Exception as exc:
                logger.debug("Suppressed exception in xchacha_stream: %s", exc)
            key32 = derive_key_from_params_json(pwd, hdr.kdf_params_json)
            master_key = key32
            if keyfile:
                master_key = _mix_with_keyfile(master_key, keyfile)

            aad_bytes = header_bytes  # compat fallback (v5 legado)
            hkdf_salt_hex = kdf_obj.get("hkdf_salt_hex")
            aad_ctx_raw = kdf_obj.get("aad_context")
            aad_context = aad_ctx_raw if isinstance(aad_ctx_raw, dict) else None
            binding_mac_hex = kdf_obj.get("binding_mac_hex")
            use_secretstream_hkdf = (aad_context is not None) and isinstance(hkdf_salt_hex, str)

            enc_key = master_key
            bind_key = None
            if use_secretstream_hkdf:
                hkdf_salt = _ensure_bytes_hex(str(hkdf_salt_hex), 32)
                aad_bytes = _aad_bytes_from_obj(aad_context)
                enc_key = derive_subkey(master_key, "CryptGuard/v5 enc", context=aad_context, salt=hkdf_salt)
                bind_key = derive_subkey(master_key, "CryptGuard/v5 bind", context=aad_context, salt=hkdf_salt)
                if not isinstance(binding_mac_hex, str):
                    raise ValueError("Falha na autenticacao")
                binding_payload = _binding_payload_bytes(kdf_obj)
                expected_mac = hmac.new(
                    bind_key, binding_payload + hdr.ss_header, hashlib.sha256
                ).digest()
                stored_mac = _ensure_bytes_hex(binding_mac_hex)
                if not hmac.compare_digest(expected_mac, stored_mac):
                    raise ValueError("Falha na autenticacao")

            # Inicializacao compativel do lado de leitura
            if _secret_bytes is not None:
                with _secret_bytes(initial=enc_key) as _kmv:
                    state = ss_init_pull_compat(hdr.ss_header, bytes(_kmv))
                try:
                    _enc_scrub = bytearray(enc_key)
                    for i in range(len(_enc_scrub)):
                        _enc_scrub[i] = 0
                except Exception:
                    pass
            else:
                _key_ba = bytearray(enc_key)
                state = ss_init_pull_compat(hdr.ss_header, bytes(_key_ba))
                for i in range(len(_key_ba)):
                    _key_ba[i] = 0

            if bind_key is not None:
                try:
                    _bind_scrub = bytearray(bind_key)
                    for i in range(len(_bind_scrub)):
                        _bind_scrub[i] = 0
                except Exception:
                    pass
            master_key = b""

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
                            raise ValueError("Falha na autenticacao")
                        (clen,) = struct.unpack(">I", ln_bytes)
                        if clen <= 0 or clen > (1 << 31):
                            raise ValueError("Falha na autenticacao")
                        c = _read_exact(f, clen)
                        try:
                            ret = ss_pull(state, c, aad_bytes)
                        except Exception as err:
                            raise ValueError("Falha na autenticacao") from err
                        ad = b""
                        if isinstance(ret, tuple) and len(ret) == 2:
                            pt, tag = ret
                        elif isinstance(ret, tuple) and len(ret) == 3:
                            pt, ad, tag = ret
                        else:
                            raise ValueError("Falha na autenticacao")
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
                                raise ValueError("Falha na autenticacao")
                            break
                        else:
                            if verify_only:
                                continue
                            if out is None:
                                raise ValueError("Falha na autenticacao")
                            out.write(pt)
                finally:
                    if out is not None:
                        try:
                            out.flush()
                        except Exception as exc:
                            logger.debug("Suppressed exception in xchacha_stream: %s", exc)
                    # tmp is closed/finalized later

                if not final_seen:
                    raise ValueError("Falha na autenticacao")

            if verify_only:
                try:
                    reset_failed_attempts(src_identifier)
                except Exception as exc:
                    logger.debug("Suppressed exception in xchacha_stream: %s", exc)
                return None

            # Decide final filename usando metadata
            # If padding was used, truncate plaintext to original size
            if out is not None and isinstance(final_meta, dict):
                try:
                    expected_size = int(final_meta.get("pt_size", -1))
                    if final_meta.get("padding") in ("4k", "16k") and expected_size >= 0:
                        out.flush()
                        out.truncate(expected_size)
                except Exception as exc:
                    logger.debug("Suppressed exception in xchacha_stream: %s", exc)
            final_dst = dst
            if isinstance(final_meta, dict):
                orig_name = final_meta.get("orig_name")
                orig_ext = final_meta.get("orig_ext")
            else:
                orig_name = None
                orig_ext = None

            # If user didn't supply out_path, prefer original filename; otherwise, handle hidden-filename mode
            if out_path is None and orig_name:
                safe_name = Path(str(orig_name)).name
                if not safe_name or safe_name in (".", ".."):
                    safe_name = "decrypted"
                final_dst = dst.parent / safe_name
            elif out_path is None and (not orig_name) and orig_ext:
                final_dst = dst.parent / f"decrypted{orig_ext}"
            elif (out_path is not None) and (not final_dst.suffix) and orig_ext:
                final_dst = final_dst.with_suffix(orig_ext)

            # Constrain final path to the target directory
            try:
                _base = dst.parent.resolve()
                _cand = final_dst.resolve()
                _ = _cand.relative_to(_base)
            except Exception:
                final_dst = dst.parent / "decrypted"

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
            # best-effort: remover referencia a chave o quanto antes
            try:
                del key32
            except Exception as exc:
                logger.debug("Suppressed exception in xchacha_stream: %s", exc)

            try:
                reset_failed_attempts(src_identifier)
            except Exception as exc:
                logger.debug("Suppressed exception in xchacha_stream: %s", exc)
            return str(final_dst.resolve())
        except Exception:
            try:
                record_failed_attempt(src_identifier)
            except Exception as exc:
                logger.debug("Suppressed exception in xchacha_stream: %s", exc)
            raise


__all__ = [
    "XChaChaStream",
    "extract_aad_bytes_from_params",
]
