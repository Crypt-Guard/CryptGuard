from __future__ import annotations
import io
import secrets

import os
import time
import zipfile
import tempfile
import hashlib
from collections.abc import Iterable
from pathlib import Path
from typing import Iterator

try:
    from .factories import decrypt, encrypt  # password: str
except Exception:  # pragma: no cover
    encrypt = decrypt = None  # type: ignore[assignment]
from .algorithms import normalize_algo


# ---------------------------------------------------------------------------
# Filesystem safety helpers
# ---------------------------------------------------------------------------
def is_within_dir(base: Path, target: Path) -> bool:
    """True if target is inside base (after resolve())."""
    try:
        base_r = Path(base).resolve()
        targ_r = Path(target).resolve()
        _ = targ_r.relative_to(base_r)
        return True
    except Exception:
        return False


def fsync_dir(path: Path) -> None:
    """Best-effort fsync on directory to ensure rename durability (POSIX)."""
    try:
        # Only attempt on platforms that support O_DIRECTORY
        if getattr(os, "O_DIRECTORY", None) is not None:
            fd = os.open(str(Path(path)), os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    except Exception:
        # Ignore: not all platforms or FS support this
        pass

def pack_enc_zip(
    inputs: Iterable[str | Path],
    out_zip: str | Path,
    password: str | bytes,
    *,
    algo: str = "AESG",
    flatten: bool = False,
) -> str:
    out_zip_p = Path(out_zip)
    out_zip_p.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(out_zip_p, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for item in inputs:
            p = Path(item)
            if p.is_dir():
                for f in p.rglob("*"):
                    if f.is_file():
                        # armazena com caminho relativo à pasta-base
                        z.write(f, (f.name if flatten else f.relative_to(p).as_posix()))
            elif p.is_file():
                z.write(p, p.name)
            else:
                raise FileNotFoundError(f"Entrada não encontrada: {p}")

    cg2_path = out_zip_p.with_suffix(".cg2")
    if encrypt is not None:
        encrypt(str(out_zip_p), password, algo=algo, out_path=str(cg2_path))
    else:
        from .cg2_ops import encrypt_to_cg2
        pwd = password.encode("utf-8") if isinstance(password, str) else password
        human = normalize_algo(algo)
        encrypt_to_cg2(str(out_zip_p), str(cg2_path), pwd, alg=human)
    return str(cg2_path)

def _safe_extract(zf: zipfile.ZipFile, out_dir: Path) -> None:
    """Safely extract a ZIP, preventing zip-slip and skipping symlinks.

    - Reject absolute paths and any component with '..'
    - Constrain extraction to out_dir using resolve/relative_to
    - Skip UNIX symlink entries
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir.resolve()
    for m in zf.infolist():
        name = Path(m.filename)
        # Reject absolute and parent traversal
        if name.is_absolute() or ".." in name.parts:
            raise ValueError(f"Tentativa de Zip Slip: {m.filename!r}")
        # Detect symlink via external_attr (UNIX) and skip
        try:
            is_symlink = ((m.external_attr >> 16) & 0o170000) == 0o120000
        except Exception:
            is_symlink = False
        if is_symlink:
            continue

        dest = (out_dir / name)
        dest_abs = dest.resolve()
        if not is_within_dir(base, dest_abs):
            raise ValueError(f"Tentativa de Zip Slip: {m.filename!r}")
        if m.is_dir():
            dest_abs.mkdir(parents=True, exist_ok=True)
            continue
        dest_abs.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(m, "r") as src, open(dest_abs, "wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)

def unpack_enc_zip(
    cg2_path: str | Path,
    out_dir: str | Path,
    password: str,
) -> str:
    cg2_p = Path(cg2_path)
    out_dir_p = Path(out_dir)
    out_dir_p.mkdir(parents=True, exist_ok=True)
    # grava zip temporário ao lado de out_dir (ex.: C:\...\saida.zip)
    tmp_zip = out_dir_p.with_suffix(".zip")

    if decrypt is not None:
        decrypt(str(cg2_p), password, out_path=str(tmp_zip))
    else:
        from .cg2_ops import decrypt_from_cg2
        pwd = password.encode("utf-8")
        decrypt_from_cg2(str(cg2_p), str(tmp_zip), pwd)

    with zipfile.ZipFile(tmp_zip, "r") as zf:
        _safe_extract(zf, out_dir_p)
    try:
        tmp_zip.unlink(missing_ok=True)
    except Exception:
        pass  # nosec B110 (fallback silencioso/Windows locks)
    return str(out_dir_p)

def write_atomic_secure(path: str | Path, data: bytes) -> None:
    """
    Atomically write bytes to a file by writing to a temp file in the same
    directory and then replacing. Best-effort fsync for durability.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=p.name + ".", dir=str(p.parent))
    try:
        with os.fdopen(fd, "wb", buffering=0) as f:
            f.write(data)
            try:
                os.fsync(f.fileno())
            except Exception:
                pass  # Best-effort on platforms without fsync
        os.replace(tmp_path, p)
        # Ensure directory entry is durable
        fsync_dir(p.parent)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass  # Windows locks, ignore

# ---------------------------------------------------------------------------
# Optional helpers for chunked IO and hashing
# ---------------------------------------------------------------------------
def read_chunks(fp: io.BufferedReader, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
    while True:
        b = fp.read(chunk_size)
        if not b:
            return
        yield b


def file_blake2s(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.blake2s()
    with open(path, "rb") as f:
        for ch in read_chunks(f, chunk_size):
            h.update(ch)
    return h.hexdigest()

# ---------------- extra GUI helpers (v2.1.5d) ----------------
def archive_folder(folder: str | Path) -> str:
    """Create a temporary ZIP from a folder and return its path (string)."""
    src = Path(folder)
    if not src.is_dir():
        raise ValueError(f"Not a directory: {src}")
    tmp_dir = Path(tempfile.gettempdir())
    # unique name based on time and random
    base = f"cg2_{int(time.time())}_{secrets.randbelow(1_000_000)}"
    out_zip = tmp_dir / f"{base}.zip"
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in src.rglob("*"):
            if p.is_dir():
                continue
            try:
                z.write(p, arcname=p.relative_to(src))
            except Exception:
                # Best-effort: skip unreadable files
                continue
    return str(out_zip)

def secure_delete(path: str | Path, passes: int = 1, *, chunk_size: int = 1024 * 1024) -> None:
    """
    Best-effort secure delete of a file:
      1) overwrite with random bytes (N passes),
      2) flush/fsync,
      3) truncate and unlink.
    Directories: rmtree best-effort.
    """
    p = Path(path)
    if not p.exists():
        return
    if p.is_dir():
        # for directories, best-effort recursive delete
        import shutil
        shutil.rmtree(p, ignore_errors=True)
        return

    try:
        size = p.stat().st_size
    except Exception:
        size = 0

    try:
        with open(p, "r+b", buffering=0) as f:
            for _ in range(max(1, int(passes))):
                f.seek(0)
                remaining = size
                while remaining > 0:
                    n = min(chunk_size, remaining)
                    f.write(os.urandom(n))
                    remaining -= n
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass  # nosec B110 (fallback silencioso/Windows locks)
            try:
                f.seek(0)
                f.truncate(0)
            except Exception:
                pass  # nosec B110 (fallback silencioso/Windows locks)
    except Exception:
        # If we couldn't open to overwrite (locked), try to rename as a fallback to break links.
        try:
            p.rename(p.with_suffix(p.suffix + ".to_delete"))
            p = p.with_suffix(p.suffix + ".to_delete")
        except Exception:
            pass  # nosec B110 (fallback silencioso/Windows locks)

    # Final unlink
    try:
        p.unlink(missing_ok=True)
    except Exception:
        # Create a .deleted marker if unlink failed
        try:
            marker = p.with_suffix(p.suffix + ".deleted")
            marker.write_text("pending-delete", encoding="utf-8")
        except Exception:
            pass  # nosec B110 (fallback silencioso/Windows locks)
# -------------------------------------------------------------
