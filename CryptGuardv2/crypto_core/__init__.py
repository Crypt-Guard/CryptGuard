"""crypto_core — API pública canônica.

Exporta:
- encrypt/decrypt (de crypto_core.factories)
- SecurityProfile e LOG_PATH

Compatibilidade de kwargs:
- alg -> algo
- output -> out_path
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Callable
from pathlib import Path

from crypto_core.logger import logger

from .algorithms import normalize_algo
from .config import LOG_PATH, SecurityProfile  # reexport
from .factories import decrypt as _decrypt_factory
from .factories import encrypt as _encrypt_factory
from .fileformat import read_header

__all__ = ["encrypt", "decrypt", "SecurityProfile", "LOG_PATH"]

if os.name == "nt":
    dll_dir = os.environ.get("SODIUM_DLL_DIR", r"C:\libsodium\bin")
    if dll_dir and os.path.isdir(dll_dir):
        os.add_dll_directory(dll_dir)


# Mapeamento de códigos curtos -> nomes internos (fonte única em algorithms)


def _compat_kwargs(kwargs: dict) -> dict:
    converted = dict(kwargs)
    if "algo" not in converted and "alg" in converted:
        converted["algo"] = converted.pop("alg")
    if "out_path" not in converted and "output" in converted:
        converted["out_path"] = converted.pop("output")
    return converted


def _guess_out_path(in_path: str) -> str:
    p = Path(in_path)
    # tentar leitura de header para detectar zip
    with contextlib.suppress(Exception):
        hdr = read_header(p)
        blob = " ".join(str(x) for x in hdr) if isinstance(hdr, tuple | list) else str(hdr)
        if "zip" in blob.lower():
            return str(p.with_suffix(".zip"))
    # fallback seguro
    return str(p.with_suffix("")) if p.suffix.lower() == ".cg2" else str(p)


def encrypt(
    in_path: str,
    password: str | bytes,
    *,
    algo: str,
    out_path: str | None = None,
    padding: str | None = None,
    hide_filename: bool = False,
    keyfile_path: str | os.PathLike[str] | None = None,
    keyfile: str | os.PathLike[str] | None = None,
    profile: SecurityProfile | None = None,
    expires_at: int | None = None,
    exp_ts: int | None = None,
    pad_block: int = 0,
    kdf_profile: str | None = None,
    progress_cb: Callable[[int, int], None] | None = None,
    **kwargs: object,
) -> str:
    compat_kwargs = _compat_kwargs(kwargs)
    override_algo = compat_kwargs.pop("algo", None)
    if override_algo is not None:
        algo = str(override_algo)
    override_out = compat_kwargs.pop("out_path", None)
    if out_path is None and override_out is not None:
        out_path = str(override_out)

    algo = normalize_algo(algo)
    pwd = password.encode() if isinstance(password, str) else password
    dst = out_path or str(Path(in_path).with_suffix(".cg2"))
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    effective_keyfile = keyfile_path if keyfile_path is not None else keyfile
    if effective_keyfile is not None and not isinstance(effective_keyfile, Path):
        effective_keyfile = Path(effective_keyfile)
    return _encrypt_factory(
        in_path,
        pwd,
        algo=algo,
        out_path=dst,
        padding=padding,
        hide_filename=hide_filename,
        keyfile=effective_keyfile,
        profile=profile,
        expires_at=expires_at,
        exp_ts=exp_ts,
        pad_block=pad_block,
        kdf_profile=kdf_profile,
        progress_cb=progress_cb,
        **compat_kwargs,
    )


def decrypt(
    cg2_path: str,
    password: str | bytes,
    *,
    out_path: str | None = None,
    verify_only: bool = False,
    keyfile_path: str | os.PathLike[str] | None = None,
    keyfile: str | os.PathLike[str] | None = None,
    progress_cb: Callable[[int, int], None] | None = None,
    **kwargs: object,
) -> str | None:
    compat_kwargs = _compat_kwargs(kwargs)
    override_out = compat_kwargs.pop("out_path", None)
    if out_path is None and override_out is not None:
        out_path = str(override_out)
    compat_kwargs.pop("verify_only", None)

    pwd = password.encode() if isinstance(password, str) else password
    dst = out_path or _guess_out_path(str(cg2_path))
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    effective_keyfile = keyfile_path if keyfile_path is not None else keyfile
    if effective_keyfile is not None and not isinstance(effective_keyfile, Path):
        effective_keyfile = Path(effective_keyfile)
    res = _decrypt_factory(
        cg2_path,
        pwd,
        out_path=dst,
        verify_only=verify_only,
        keyfile=effective_keyfile,
        progress_cb=progress_cb,
        **compat_kwargs,
    )
    return None if verify_only else (res or dst)


try:
    from modules.keyguard.integrate import attach_keyguard_sidebar

    if os.environ.get("CG_ENABLE_TK_KEYGUARD") == "1":
        attach_keyguard_sidebar(None)  # tenta descobrir o root e o self.vault
except Exception as e:
    logger.warning("KeyGuard sidebar indisponível: %s", e)
