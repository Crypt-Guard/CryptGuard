from __future__ import annotations

import os
import tempfile
from pathlib import Path


class SecureTempFile:
    """
    Temporary file helper with safe finalize via os.replace.
    On POSIX, delete=False to allow rename; on Windows we also use delete=False
    to ensure we can finalize, and we best-effort remove on close if not finalized.
    """

    def __init__(self, suffix: str = "", dir: str | None = None):
        self._fh = tempfile.NamedTemporaryFile(delete=False, suffix=suffix, dir=dir)
        self.path = Path(self._fh.name)
        # Reinforce restrictive permissions where applicable
        try:
            os.chmod(self._fh.name, 0o600)
        except Exception:
            pass
        self._finalized = False

    @property
    def fh(self):
        return self._fh

    def write(self, b: bytes):
        self._fh.write(b)

    def flush(self):
        self._fh.flush()
        try:
            os.fsync(self._fh.fileno())
        except Exception:
            pass

    def fileno(self):
        return self._fh.fileno()

    def finalize(self, dst: Path):
        self.flush()
        self._fh.close()
        # Se o arquivo temporário não estiver no mesmo diretório do destino,
        # fazer staging no diretório do destino para preservar atomicidade
        dst = Path(dst)
        if Path(self.path).parent != dst.parent:
            try:
                import secrets
                stage = dst.parent / (dst.name + f".stage.{secrets.token_hex(8)}")
                os.replace(self.path, stage)
                self.path = stage
            except OSError as ex:
                # EXDEV indica dispositivos diferentes; copiar para temp no destino
                if getattr(ex, "errno", None) == getattr(os, "EXDEV", 18):
                    import shutil, tempfile
                    with open(self.path, "rb") as src, tempfile.NamedTemporaryFile("wb", delete=False, dir=str(dst.parent)) as tmp:
                        shutil.copyfileobj(src, tmp)
                        tmp.flush()
                        try:
                            os.fsync(tmp.fileno())
                        except Exception:
                            pass
                        tmp_path = Path(tmp.name)
                    try:
                        os.replace(tmp_path, dst)
                        self._finalized = True
                        # fsync do diretório (POSIX)
                        try:
                            dir_flag = getattr(os, "O_DIRECTORY", None)
                            if dir_flag is not None:
                                dir_fd = os.open(str(dst.parent), dir_flag)
                                try:
                                    os.fsync(dir_fd)
                                finally:
                                    os.close(dir_fd)
                        except Exception:
                            pass
                        return
                    finally:
                        try:
                            os.remove(self.path)
                        except Exception:
                            pass
                else:
                    raise
        os.replace(self.path, dst)
        self._finalized = True
        # fsync directory to ensure durability of the rename (POSIX)
        try:
            # Only attempt if os.O_DIRECTORY is available
            dir_flag = getattr(os, "O_DIRECTORY", None)
            if dir_flag is not None:
                dir_fd = os.open(str(Path(dst).parent), dir_flag)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        except Exception:
            pass

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass
        if not self._finalized and self.path.exists():
            try:
                os.remove(self.path)
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
