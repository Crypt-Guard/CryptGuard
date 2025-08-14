from __future__ import annotations
import secrets

import os
import time
import zipfile
import tempfile
import random
from collections.abc import Iterable
from pathlib import Path

try:
    from .factories import decrypt, encrypt  # password: str
except Exception:  # pragma: no cover
    encrypt = decrypt = None  # type: ignore[assignment]

def pack_enc_zip(
    inputs: Iterable[str | Path],
    out_zip: str | Path,
    password: str,
    *,
    algo: str = "AESG",
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
                        z.write(f, f.relative_to(p).as_posix())
            elif p.is_file():
                z.write(p, p.name)
            else:
                raise FileNotFoundError(f"Entrada não encontrada: {p}")

    cg2_path = out_zip_p.with_suffix(".cg2")
    if encrypt is not None:
        encrypt(str(out_zip_p), password, algo=algo, out_path=str(cg2_path))
    else:
        from .cg2_ops import encrypt_to_cg2
        alg_map = {"AESG": "AES-256-GCM", "ACTR": "AES-256-CTR",
                   "XC20": "XChaCha20-Poly1305", "CH20": "ChaCha20-Poly1305"}
        pwd = password.encode("utf-8")
        encrypt_to_cg2(str(out_zip_p), str(cg2_path), pwd, alg=alg_map.get(algo, algo))
    return str(cg2_path)

def _safe_extract(zf: zipfile.ZipFile, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for m in zf.infolist():
        dest = out_dir / m.filename
        dest_abs = dest.resolve()
        if not str(dest_abs).startswith(str(out_dir.resolve())):
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
