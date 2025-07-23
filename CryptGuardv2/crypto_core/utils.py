"""
utils.py  –  utilidades gerais (v2025‑07)

Inclui:
• escrita atômica segura (chmod 600)
• helpers JSON (bytes ↔ dict)
• nome único randomizado
• secure‑delete (arquivo ou pasta recursiva)
• verificação de expiração (campo "exp" nos metadados)
• cálculo de velocidade humana (bytes/s → string)
• empacote / desempacote ZIP contendo *.enc + *.enc.meta*
"""

from __future__ import annotations

import os, json, secrets, tempfile, shutil, time, datetime, zipfile
from pathlib import Path
from typing   import Tuple

# ───── extensões & tamanhos ────────────────────────────────────────────
ENC_EXT  = ".enc"
META_EXT = ".meta"

# Secure‑delete escreve blocos de 1 MiB
SECURE_DELETE_CHUNK_SIZE = 1_048_576  # 1 MiB

# ───────────────────────── Expiração helpers ───────────────────────────
class ExpiredFileError(Exception):
    """Arquivo ultrapassou a data de validade."""

def check_expiry(meta: dict, skew_seconds: int = 0) -> None:
    """
    Levanta `ExpiredFileError` se o campo ``"exp"`` (epoch UTC seg) estiver no passado.

    Se o campo não existir, simplesmente retorna.
    `skew_seconds` define tolerância de relógio (default 0).
    """
    exp = meta.get("exp")
    if exp is None:
        return
    if time.time() > exp + skew_seconds:
        ts = datetime.datetime.utcfromtimestamp(exp).strftime("%Y‑%m‑%d %H:%M:%S")
        raise ExpiredFileError(f"Arquivo expirado em {ts} UTC")

# ───────────────────────── Escrita atômica ─────────────────────────────
def write_atomic_secure(dest: str | Path, data: bytes) -> None:
    """Grava *data* em *dest* com permissão 600, de forma atômica."""
    dest = Path(dest)
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

# ───────────────────────── JSON helpers ────────────────────────────────
def to_json_bytes(obj):  return json.dumps(obj, separators=(",", ":")).encode()
def from_json_bytes(b):  return json.loads(b.decode())

# ───────────────────────── Nome único ──────────────────────────────────
def generate_unique_filename(path: str | Path) -> Path:
    """Retorna um Path com sufixo hex aleatório para evitar colisão."""
    p = Path(path)
    unique = f"{p.stem}_{secrets.token_hex(4)}{p.suffix}"
    return p.with_name(unique)

# ───────────────────────── Secure‑delete ───────────────────────────────
def secure_delete(path: str | os.PathLike, passes: int = 3) -> None:
    """
    Sobrescreve e remove um *arquivo* ou cada arquivo em um *diretório* (recursivo).

    • `passes` ≥ 1 define quantas vezes cada byte será sobregravado.
    • Diretórios são percorridos com `.rglob('*')`.
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

    length       = p.stat().st_size
    full_chunks  = length // SECURE_DELETE_CHUNK_SIZE
    remainder    = length % SECURE_DELETE_CHUNK_SIZE
    with p.open("r+b", buffering=0) as f:
        for _ in range(max(1, passes)):
            f.seek(0)
            # chunks cheios
            for _ in range(full_chunks):
                f.write(secrets.token_bytes(SECURE_DELETE_CHUNK_SIZE))
            # resto
            if remainder:
                f.write(secrets.token_bytes(remainder))
            f.flush(); os.fsync(f.fileno())
    p.unlink(missing_ok=True)

# ───────────────────────── Velocidade humana ───────────────────────────
def human_speed(done: int, elapsed: float) -> str:
    """
    Converte *done* (bytes) / *elapsed* (s) → string “x MB/s”.
    """
    if elapsed == 0:
        return "– MB/s"
    mbps = done / 1_048_576 / elapsed
    return f"{mbps:,.1f} MB/s"

# ───────────────────────── Archive helper (ZIP genérico) ───────────────
def archive_folder(folder_path: str | Path) -> Path:
    """
    Compacta *folder_path* em ZIP recursivo.
    Retorna o **path** do ZIP criado.
    """
    folder = Path(folder_path)
    zip_path = folder.with_suffix('.zip')
    shutil.make_archive(str(folder), 'zip', root_dir=folder)
    return zip_path

# ───────────────────────── ZIP helpers *.enc + *.meta* ─────────────────
def pack_enc_zip(enc_path: Path) -> Path:
    """
    Cria ``<arquivo>.zip`` contendo *arquivo.enc* + *arquivo.enc.meta*,
    remove os originais e retorna o Path do ZIP.
    """
    meta_path = enc_path.with_suffix(enc_path.suffix + META_EXT)
    zip_path  = enc_path.with_suffix('.zip')
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(enc_path,  arcname=enc_path.name)
        if meta_path.exists():
            zf.write(meta_path, arcname=meta_path.name)
    enc_path.unlink(missing_ok=True)
    meta_path.unlink(missing_ok=True)
    return zip_path

def unpack_enc_zip(zip_path: Path) -> Tuple[Path, tempfile.TemporaryDirectory]:
    """
    Extrai ZIP contendo *.enc* + *.meta* para diretório temporário
    e retorna (<Path para .enc extraído>, <TemporaryDirectory>).

    Mantenha o objeto `TemporaryDirectory` vivo até terminar o uso.
    """
    td = tempfile.TemporaryDirectory()
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(td.name)
        enc_name = next(n for n in zf.namelist() if n.endswith(ENC_EXT))
    return Path(td.name) / enc_name, td
