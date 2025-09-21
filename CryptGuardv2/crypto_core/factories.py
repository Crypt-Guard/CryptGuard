# ============================================================================
# === Canonical API (v2.1.5c) -- single public face ==========================
from __future__ import annotations

from pathlib import Path as _Path
import contextlib as _ctx
import logging as _logging
import os as _os
import re as _re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import SecurityProfile  # noqa: F401


# Algorithm normalization kept for backward compatibility (unused in v5)

# New v5 routing utilities
from .fileformat_v5 import read_header_version_any as _read_ver_any

# Helpers: atomic write (+fsync) and log redaction
def _fsync_file_and_dir(file_path: str | _Path) -> None:
    """Flush file contents and the containing directory entry to disk."""
    p = _Path(file_path)
    try:
        with open(p, "rb+") as fh:
            fh.flush()
            _os.fsync(fh.fileno())
    except Exception:
        pass
    # fsync directory entry (best-effort)
    try:
        dfd = _os.open(str(p.parent), _os.O_RDONLY)
        try:
            _os.fsync(dfd)
        finally:
            _os.close(dfd)
    except Exception:
        pass

def _atomic_target(final_path: str | _Path) -> tuple[_Path, _Path]:
    """Return (tmp, final) paths in the same directory."""
    final = _Path(final_path)
    tmp = final.with_suffix(final.suffix + ".part")
    final.parent.mkdir(parents=True, exist_ok=True)
    return tmp, final

@_ctx.contextmanager
def _redact_logs_for_operation(*names_to_hide: str):
    """
    Temporarily install a logging Filter that redacts:
      - any appearance of provided names (e.g., source file name),
      - occurrences of orig_name= / "orig_name": in structured logs.
    """
    root = _logging.getLogger()
    patterns = []
    for nm in names_to_hide:
        if nm:
            patterns.append(_re.compile(_re.escape(str(nm))))
    patterns.append(_re.compile(r'("orig_name"\s*:\s*")[^"]+("")?'))
    patterns.append(_re.compile(r"(orig_name\s*=\s*')[^']+(')"))
    patterns.append(_re.compile(r'(orig_name\s*=\s*")[^"]+(")'))

    class _RedactFilter(_logging.Filter):
        def filter(self, record: _logging.LogRecord) -> bool:
            try:
                msg = record.getMessage()
                for pat in patterns:
                    try:
                        if pat.groups >= 2:
                            msg = pat.sub(r"\1[hidden]\2", msg)
                        else:
                            msg = pat.sub("[hidden]", msg)
                    except Exception:
                        msg = pat.sub("[hidden]", msg)
                record.msg = msg
                record.args = ()
            except Exception:
                pass
            return True

    filt = _RedactFilter()
    root.addFilter(filt)
    try:
        yield
    finally:
        root.removeFilter(filt)

def encrypt(
    in_path: str | _Path,
    password: str | bytes,
    *,
    algo: str,  # ignored in v5 (kept for compatibility)
    out_path: str | _Path,
    profile: "SecurityProfile" | None = None,  # noqa: UP037
    expires_at: int | None = None,
    exp_ts: int | None = None,
    progress_cb=None,
    pad_block: int = 0,
    kdf_profile: str | None = None,
    padding: str | None = None,
    keyfile: str | _Path | None = None,
    hide_filename: bool = False,
) -> str:
    # Force v5 encryption via SecretStream (PyNaCl required)
    # UI-supplied 'algo' is ignored; always XChaCha20-Poly1305 SecretStream.
    from .xchacha_stream import XChaChaStream

    if isinstance(password, str):
        password = password.encode()
    src = _Path(in_path)
    dst = _Path(out_path)
    if dst.suffix.lower() != ".cg2":
        dst = dst.with_suffix(".cg2")

    # Resolve padding policy preference
    pad_policy = None
    if isinstance(padding, str):
        p = padding.strip().lower()
        if p in ("off", "4k", "16k"):
            pad_policy = p
    if pad_policy is None:
        # Map pad_block to the new padding policy: off/4k/16k
        if pad_block in (4096, 4 * 1024):
            pad_policy = "4k"
        elif pad_block in (16384, 16 * 1024):
            pad_policy = "16k"
        elif pad_block == 0:
            # Default: enable 4k padding to reduce plaintext size leakage
            pad_policy = "4k"
        else:
            pad_policy = "off"

    # Resolve KDF profile
    kprof = (kdf_profile or "INTERACTIVE").upper()
    if kprof not in ("INTERACTIVE", "SENSITIVE"):
        kprof = "INTERACTIVE"

    # accept both names and normalise: expires_at has priority; otherwise exp_ts is used
    _exp_effective = None
    try:
        _exp_effective = int(expires_at) if expires_at is not None else (
            int(exp_ts) if exp_ts is not None else None
        )
    except Exception:
        _exp_effective = None

    src_name = src.name
    # Atomic write with redacted logs when hiding filename
    with _redact_logs_for_operation(src_name) if hide_filename else _ctx.nullcontext():
        tmp, final = _atomic_target(dst)
        res_tmp = XChaChaStream().encrypt_file(
            src,
            password,
            out_path=str(tmp),
            kdf_profile=kprof,
            padding=pad_policy,
            keyfile=str(keyfile) if keyfile else None,
            hide_filename=bool(hide_filename),
            expires_at=_exp_effective,
        )
        _fsync_file_and_dir(res_tmp)
        _os.replace(res_tmp, final)
        _fsync_file_and_dir(final)
        return str(_Path(final).resolve())

def decrypt(
    in_path: str | _Path,
    password: str | bytes,
    *,
    out_path: str | _Path | None = None,
    verify_only: bool = False,
    progress_cb=None,
    keyfile: str | _Path | None = None,
) -> str | None:
    src = _Path(in_path)
    if isinstance(password, str):
        password = password.encode()

    dst = _Path(out_path) if out_path is not None else None

    try:
        ver = _read_ver_any(src)
    except Exception:
        ver = 0

    if ver >= 5:
        from .xchacha_stream import XChaChaStream
        if verify_only:
            XChaChaStream().decrypt_file(
                src,
                password,
                out_path=None,
                verify_only=True,
                keyfile=str(keyfile) if keyfile else None,
            )
            return None
        if dst is None:
            raise ValueError("out_path must be provided for decryption when verify_only is False")
        # Passa o destino final ao core; o proprio core faz finalize() atomico e decide sufixo
        res = XChaChaStream().decrypt_file(
            src,
            password,
            out_path=str(dst),
            verify_only=False,
            keyfile=str(keyfile) if keyfile else None,
        )
        return str(_Path(res).resolve()) if res else None
    else:
        # legacy v1-v4
        from .legacy.decrypt_legacy import decrypt_file as _dec_legacy
        if dst is None:
            dst = src.with_suffix(".tmp")
        res = _dec_legacy(src, password, out_path=str(dst), verify_only=verify_only)
        if verify_only:
            return None
        return str(_Path(res).resolve())


def Encrypt(*args, **kwargs):
    if "algo" not in kwargs and "alg" in kwargs:
        kwargs["algo"] = kwargs.pop("alg")
    if "out_path" not in kwargs and "output" in kwargs:
        kwargs["out_path"] = kwargs.pop("output")
    return encrypt(*args, **kwargs)

def Decrypt(*args, **kwargs):
    if "out_path" not in kwargs and "output" in kwargs:
        kwargs["out_path"] = kwargs.pop("output")
    return decrypt(*args, **kwargs)
# ===========================================================================

def verify(in_path: str | _Path, password: str | bytes, *, keyfile: str | _Path | None = None) -> bool:
    """Verify authentication without leaving artifacts on disk.

    Returns True if decryption/authentication succeeds, False otherwise.
    """
    try:
        decrypt(in_path, password, out_path=None, verify_only=True, keyfile=keyfile)
        return True
    except Exception:
        return False

# convenient aliases
cg_encrypt = encrypt
cg_decrypt = decrypt
