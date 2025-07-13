"""
Utilidades gerais: escrita atómica, JSON e exclusão segura.
"""
import os, json, secrets, tempfile
from pathlib import Path

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
