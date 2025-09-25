from __future__ import annotations

import stat
import struct
import zipfile
from collections.abc import Iterable
from collections.abc import Iterable as _Iterable
from pathlib import Path

from .utils import is_within_dir
from .utils import pack_enc_zip as _pack_enc_zip

_ZIP_TS = (2020, 1, 1, 0, 0, 0)  # canonical timestamp to reduce metadata leaks


def _iter_files(base: Path) -> _Iterable[Path]:
    base = Path(base)
    for p in base.rglob("*"):
        if p.is_file():
            yield p


def make_zip_from_dir(src_dir: Path, out_zip: Path, *, exclude_hidden: bool = True) -> Path:
    """
    Create a .zip from src_dir with safer defaults:
      - ignore symlinks
      - arcname uses relative POSIX path (no '..')
      - normalize timestamps
      - optionally skip hidden files
    """
    src_dir = Path(src_dir).resolve()
    out_zip = Path(out_zip)
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fp in _iter_files(src_dir):
            # skip symlinks when lstat reveals them
            try:
                st = fp.lstat()
                if stat.S_ISLNK(st.st_mode):
                    continue
            except Exception:
                continue
            rel = fp.relative_to(src_dir)
            if exclude_hidden and any(part.startswith(".") for part in rel.parts):
                continue
            rel_posix = rel.as_posix()
            if ".." in Path(rel_posix).parts or rel_posix.startswith("/"):
                continue
            zi = zipfile.ZipInfo(rel_posix, date_time=_ZIP_TS)
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(fp, "rb") as fh:
                zf.writestr(zi, fh.read())
    return out_zip


def safe_extract_zip(zip_path: Path, dst_dir: Path) -> None:
    """
    Safely extract a zip file, preventing zip-slip and skipping symlinks.
    """
    zip_path = Path(zip_path)
    dst_dir = Path(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)
    base = dst_dir.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for m in zf.infolist():
            name = Path(m.filename)
            if name.is_absolute() or ".." in name.parts:
                continue
            # Detect symlink via external_attr (UNIX)
            try:
                is_symlink = ((m.external_attr >> 16) & 0o170000) == 0o120000
            except Exception:
                is_symlink = False
            if is_symlink:
                continue
            target = (dst_dir / name).resolve()
            if not is_within_dir(base, target):
                continue
            if m.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(m) as src, open(target, "wb") as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    dst.write(chunk)


def pack_u32(value: int) -> bytes:
    """Pack an unsigned 32-bit integer into big-endian bytes."""
    if not isinstance(value, int):
        raise TypeError("value must be an int")
    if value < 0 or value > 0xFFFFFFFF:
        raise ValueError("value out of range for u32")
    return struct.pack(">I", value)


def unpack_u32(data: bytes | bytearray | memoryview) -> int:
    """Unpack a big-endian unsigned 32-bit integer from bytes."""
    mv = memoryview(data)
    if mv.nbytes != 4:
        raise ValueError("data must be exactly 4 bytes")
    return struct.unpack(">I", mv.tobytes())[0]


def pack_enc_zip(
    inputs: Iterable[str | Path],
    out_zip: str | Path,
    password: str | bytes,
    *,
    algo: str = "AESG",
) -> str:
    """Compat wrapper: delegate to utils.pack_enc_zip with flatten=True.

    Maintains prior signature accepting password as str|bytes.
    """
    return _pack_enc_zip(inputs, out_zip, password, algo=algo, flatten=True)


__all__ = [
    "pack_u32",
    "unpack_u32",
    "pack_enc_zip",
    "make_zip_from_dir",
    "safe_extract_zip",
]
