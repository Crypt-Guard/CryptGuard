# utils.py
"""
Utility functions: clearing screen, generating unique filenames, ephemeral tokens, etc.
"""

import os
import datetime
import secrets
import subprocess
import shutil
import time
from pathlib import Path
from crypto_core.file_permissions import secure_permissions

def clear_screen() -> None:
    try:
        subprocess.call('cls' if os.name == 'nt' else 'clear', shell=True)
    except Exception:
        pass

def generate_ephemeral_token(n_bits: int = 128) -> str:
    num = int.from_bytes(secrets.token_bytes((n_bits + 7) // 8), 'big')
    return hex(num)[2:]

def generate_random_number(n_bits: int) -> int:
    random_bytes = secrets.token_bytes((n_bits + 7) // 8)
    number = int.from_bytes(random_bytes, 'big')
    excess = (len(random_bytes) * 8 - n_bits)
    if excess > 0:
        number >>= excess
    return number

def generate_unique_filename(prefix: str, extension: str = ".enc") -> str:
    prefix = prefix.replace("/", "_").replace("\\", "_").replace("..", "_")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    random_component = hex(generate_random_number(64))[2:]
    return f"{prefix}_{timestamp}_{random_component}{extension}"


def write_atomic_secure(path: Path, data: bytes) -> None:
    import tempfile

    backup_path = None
    if path.exists():
        backup_path = path.with_suffix(path.suffix + '.backup')
        shutil.copy2(path, backup_path)
        secure_permissions(backup_path)

    with tempfile.NamedTemporaryFile(
        mode='wb', dir=path.parent, prefix=f'.{path.stem}_tmp_', suffix=path.suffix, delete=False
    ) as tmp:
        tmp.write(data)
        tmp.flush()
        os.fsync(tmp.fileno())
        temp_path = Path(tmp.name)

    secure_permissions(temp_path)

    try:
        temp_path.replace(path)
        secure_permissions(path)
        if backup_path and backup_path.exists():
            backup_path.unlink()
    except Exception as e:
        if backup_path and backup_path.exists():
            backup_path.replace(path)
        temp_path.unlink()
        raise

    _cleanup_temp_files(path.parent, path.stem)


def _cleanup_temp_files(directory: Path, prefix: str) -> None:
    try:
        pattern = f'.{prefix}_tmp_*'
        cutoff = time.time() - 3600
        for temp_file in directory.glob(pattern):
            try:
                if temp_file.stat().st_mtime < cutoff:
                    temp_file.unlink()
            except Exception:
                pass
    except Exception:
        pass
