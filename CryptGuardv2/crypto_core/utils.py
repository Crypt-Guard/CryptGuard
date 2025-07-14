"""
Utilidades gerais: escrita atómica, JSON e exclusão segura.
"""
import os, json, secrets, tempfile
from pathlib import Path
import zipfile, shutil

# ───── gravação atómica ────────────────────────────────────────────────
def write_atomic_secure(dest: Path, data: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, dest)
        dest.chmod(0o600)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

# ───── json helpers ────────────────────────────────────────────────────
def to_json_bytes(obj):   return json.dumps(obj, separators=(",",":")).encode()
def from_json_bytes(b):   return json.loads(b.decode())

# ───── nome único ──────────────────────────────────────────────────────
def generate_unique_filename(base:str, ext:str="") -> str:
    return f"{base}_{secrets.token_hex(4)}{ext}"

# ───── exclusão segura ─────────────────────────────────────────────────
def secure_delete(path:str|os.PathLike, passes:int=1) -> None:
    """Sobrescreve o arquivo com bytes aleatórios e remove."""
    p = Path(path)
    if not p.exists(): return
    length = p.stat().st_size
    with p.open("r+b", buffering=0) as f:
        for _ in range(max(1, passes)):
            f.seek(0)
            f.write(secrets.token_bytes(length))
            f.flush(); os.fsync(f.fileno())
    p.unlink()

# ─── add after secure_delete() ──────────────────────────────────────────
def archive_folder(src_path: Path | str, fmt: str = "zip") -> Path:
    """
    Compress *src_path* (file OR directory) into a ZIP que fica na
    mesma pasta do item original.  Retorna o Path do ZIP.
    """
    src = Path(src_path)
    if fmt != "zip":
        raise ValueError("Only ZIP supported for now.")

    parent = src.parent
    zip_name = f"{src.stem}_{secrets.token_hex(4)}.zip"
    dst = parent / zip_name

    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zf:
        if src.is_dir():
            for p in src.rglob("*"):
                if p.is_file():
                    zf.write(p, p.relative_to(src))
        else:
            zf.write(src, src.name)
    return dst
