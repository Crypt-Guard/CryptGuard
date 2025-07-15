"""
Utilidades gerais: escrita atômica, JSON e exclusão segura.
"""
import os, json, secrets, tempfile
from pathlib import Path
from typing import Tuple
import zipfile

# These constants are needed by the new functions.
# Assuming they are defined here as the .config module is not available.
ENC_EXT = ".enc"
META_EXT = ".meta"

# Chunk size for secure deletion (1 MiB)
SECURE_DELETE_CHUNK_SIZE = 1024 * 1024

# ───── gravação atómica ────────────────────────────────────────────────
def write_atomic_secure(dest: str | Path, data: bytes) -> None:
    dest = Path(dest)  # Ensure dest is always a Path object
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
def generate_unique_filename(path: str | Path) -> Path:
    """
    Generate a unique filename by appending a random hex suffix to the stem.
    Returns a Path object.
    """
    p = Path(path)
    new_name = f"{p.stem}_{secrets.token_hex(4)}{p.suffix}"
    return p.with_name(new_name)

# ───── exclusão segura ─────────────────────────────────────────────────
def secure_delete(path:str|os.PathLike, passes:int=3) -> None:
    """
    Overwrite a *file* **ou** cada arquivo dentro de um *diretório*
    (recursivamente) e, por fim, removê-lo(s).
    """
    p = Path(path)
    if p.is_dir():
        for child in p.rglob('*'):
            secure_delete(child, passes=passes)
        try:
            p.rmdir()
        except OSError:
            pass
        return
    if not p.is_file():
        return
    
    length = p.stat().st_size
    full_chunks = length // SECURE_DELETE_CHUNK_SIZE
    remainder = length % SECURE_DELETE_CHUNK_SIZE
    
    with p.open("r+b", buffering=0) as f:
        for _ in range(max(1, passes)):
            f.seek(0)
            # Write full chunks
            for _ in range(full_chunks):
                chunk = secrets.token_bytes(SECURE_DELETE_CHUNK_SIZE)
                f.write(chunk)
            # Write remainder if any
            if remainder > 0:
                chunk = secrets.token_bytes(remainder)
                f.write(chunk)
            f.flush(); os.fsync(f.fileno())
    p.unlink()

# ───────────────────────── ZIP helpers ─────────────────────────
def pack_enc_zip(enc_path: Path) -> Path:
    """
    Cria ``<arquivo>.zip`` contendo *arquivo.enc* e *arquivo.enc.meta*,
    apaga os originais e devolve o caminho do ZIP.
    """
    meta_path = enc_path.with_suffix(enc_path.suffix + META_EXT)
    zip_path  = enc_path.with_suffix('.zip')
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(enc_path, arcname=enc_path.name)
        if meta_path.exists():
            zf.write(meta_path, arcname=meta_path.name)
    enc_path.unlink(missing_ok=True)
    meta_path.unlink(missing_ok=True)
    return zip_path

def unpack_enc_zip(zip_path: Path) -> Tuple[Path, tempfile.TemporaryDirectory]:
    """
    Extrai ZIP contendo *.enc* + *.meta* para um diretório temporário
    e devolve: (caminho_para_enc, objeto_TemporaryDirectory).
    O chamador deve manter o objeto vivo até terminar a operação.
    """
    td = tempfile.TemporaryDirectory()
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(td.name)
        enc_name = next(n for n in zf.namelist() if n.endswith(ENC_EXT))
    return Path(td.name) / enc_name, td
