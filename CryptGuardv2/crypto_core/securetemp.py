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

