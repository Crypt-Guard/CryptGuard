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
