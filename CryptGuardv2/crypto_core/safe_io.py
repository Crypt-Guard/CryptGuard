"""
Operações de I/O seguras: escrita atômica e permissões seguras
"""

import os
import tempfile
from pathlib import Path
import contextlib
from typing import IO, ContextManager, Any

DEFAULT_FILE_MODE = 0o600
DEFAULT_DIR_MODE = 0o700

def _fsync_best_effort(fd: int) -> None:
    """Tenta forçar a sincronização do descritor de arquivo com o disco."""
    try:
        os.fsync(fd)
    except (OSError, AttributeError):
        pass

def secure_mkdir(path: str | Path, mode: int = DEFAULT_DIR_MODE) -> Path:
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(path, mode)
    return path

def atomic_write_bytes(path: str | Path, data: bytes, mode: int = DEFAULT_FILE_MODE) -> None:
    if not data:
        raise ValueError("Dados não podem ser vazios")

    path = Path(path)
    if not path.parent.exists():
        secure_mkdir(path.parent)

    tmp_file = tempfile.NamedTemporaryFile(
        mode="wb", dir=path.parent, delete=False, suffix=".tmp"
    )
    tmp_path = Path(tmp_file.name)

    try:
        with tmp_file:
            tmp_file.write(data)
            tmp_file.flush()
            _fsync_best_effort(tmp_file.fileno())

        os.rename(tmp_path, path)
        with contextlib.suppress(OSError):
            os.chmod(path, mode)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

def atomic_write_text(
    path: str | Path, text: str, mode: int = DEFAULT_FILE_MODE, encoding: str = "utf-8"
) -> None:
    data = text.encode(encoding)
    atomic_write_bytes(path, data, mode)

class AtomicFileWriter(ContextManager[IO[bytes]]):
    def __init__(self, path: str | Path, mode: int = DEFAULT_FILE_MODE):
        self.path = Path(path)
        self.mode = mode
        self.tmp_file: IO[bytes] | None = None
        self._tmp_path: Path | None = None

    def __enter__(self) -> IO[bytes]:
        if not self.path.parent.exists():
            secure_mkdir(self.path.parent)

        self.tmp_file = tempfile.NamedTemporaryFile(
            mode="wb", dir=self.path.parent, delete=False, suffix=".tmp"
        )
        self._tmp_path = Path(self.tmp_file.name)
        return self.tmp_file

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self.tmp_file is None or self._tmp_path is None:
            return

        if exc_type is None:
            self.tmp_file.flush()
            _fsync_best_effort(self.tmp_file.fileno())
            self.tmp_file.close()
            try:
                os.rename(self._tmp_path, self.path)
                with contextlib.suppress(OSError):
                    os.chmod(self.path, self.mode)
            except Exception:
                self._tmp_path.unlink(missing_ok=True)
                raise
        else:
            self.tmp_file.close()
            self._tmp_path.unlink(missing_ok=True)