"""
utils.py  –  utilidades gerais (v2025‑07)

Inclui:
• escrita atômica segura (chmod 600)
• helpers JSON (bytes ↔ dict)
• nome único randomizado
• secure‑delete (arquivo ou pasta recursiva)
• verificação de expiração (campo "exp" nos metadados)
• cálculo de velocidade humana (bytes/s → string)
• utilidades diversas (CG2-only)
"""

from __future__ import annotations

import os, json, secrets, tempfile, shutil, time, datetime, zipfile
from pathlib import Path
from typing   import Tuple
import re
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
    """
    Retorna *path* se ele ainda não existe.
    Caso exista, gera “<nome> (1).ext”, “<nome> (2).ext”… evitando
    correntes intermináveis de `_abcd1234_ef9876…`.
    """
    p = Path(path)
    if not p.exists():
        return p

    # Remove eventuais sufixos _<hex8> já existentes (retro‑compat)
    base_stem = re.sub(r"_([0-9a-fA-F]{8})$", "", p.stem)
    counter = 1
    while True:
        candidate = p.with_name(f"{base_stem} ({counter}){p.suffix}")
        if not candidate.exists():
            return candidate
        counter += 1

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
    folder = Path(folder_path)
    if not folder.is_dir():
        raise NotADirectoryError(folder)
    zip_path = folder.with_suffix(".zip")
    shutil.make_archive(str(folder), "zip", root_dir=folder)
    return zip_path

# (ZIP helpers de legado removidos – CG2-only)


def human_size(n: int) -> str:
    units = ["B","KiB","MiB","GiB","TiB"]
    s = float(n); i = 0
    while s >= 1024 and i < len(units)-1:
        s /= 1024; i += 1
    return f"{s:.2f} {units[i]}"



def detect_algo_from_header(path) -> str | None:
    try:
        from .fileformat import read_header
        hdr, *_ = read_header(Path(path))
        return getattr(hdr, "alg", None)
    except Exception:
        return None


def pack_enc_zip(paths, dest_zip, password: str, algo: str = "AESG", **kw) -> str:
    """Compacta `paths` em ZIP e cifra o ZIP com a API disponível.
    Retorna caminho do arquivo cifrado.
    """
    from zipfile import ZipFile, ZIP_DEFLATED
    from pathlib import Path
    import tempfile
    paths = [Path(p) for p in (paths if isinstance(paths, (list, tuple)) else [paths])]
    dest_zip = Path(dest_zip)
    # cria zip temporário se o destino final for o .cg2
    tmp_zip = dest_zip if dest_zip.suffix.lower() == ".zip" else Path(tempfile.gettempdir()) / ("cg2_pkg_" + paths[0].name + ".zip")
    with ZipFile(tmp_zip, "w", ZIP_DEFLATED) as z:
        for p in paths:
            if p.is_dir():
                for sub in p.rglob("*"):
                    if sub.is_file():
                        z.write(sub, arcname=sub.relative_to(p))
            else:
                z.write(p, arcname=p.name)
    # cifra o zip
    try:
        from .factories import encrypt as _enc
        out = _enc(str(tmp_zip), password, algo=algo, **kw)
        return out
    except Exception:
        from .cg2_ops import encrypt_to_cg2
        algo_map = {"AESG":"AES-256-GCM","ACTR":"AES-256-CTR","XC20":"XChaCha20-Poly1305","CH20":"ChaCha20-Poly1305"}
        human = algo_map.get(algo, algo)
        out = tmp_zip.with_suffix(".cg2")
        pwd = password.encode() if isinstance(password, str) else password
        encrypt_to_cg2(str(tmp_zip), str(out), pwd, alg=human, **kw)
        return str(out)
