"""Secure temporary file handling utilities."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .log_utils import log_best_effort


class SecureTempFile:
    """
    Temporary file helper with safe finalize via os.replace.
    On POSIX, delete=False to allow rename; on Windows we also use delete=False
    to ensure we can finalize, and we best-effort remove on close if not finalized.
    """

    def __init__(self, suffix: str = "", dir: str | None = None):
        fd, path = tempfile.mkstemp(suffix=suffix, dir=dir)
        self.path = Path(path)
        self._file = os.fdopen(fd, "w+b", buffering=0)
        # Reinforce restrictive permissions where applicable
        try:
            os.chmod(self.path, 0o600)
        except Exception as exc:
            log_best_effort(__name__, exc)
        self._finalized = False

    @property
    def fh(self):
        return self._file

    def write(self, b: bytes):
        self._file.write(b)

    def flush(self):
        self._file.flush()
        try:
            os.fsync(self._file.fileno())
        except Exception as exc:
            log_best_effort(__name__, exc)

    def fileno(self):
        return self._file.fileno()

    def finalize(self, dst: Path):
        self.flush()
        self._file.close()
        dst = Path(dst)
        try:
            if self.path.parent != dst.parent:
                try:
                    import secrets

                    stage = dst.parent / (dst.name + f".stage.{secrets.token_hex(8)}")
                    os.replace(self.path, stage)
                    self.path = stage
                except OSError as ex:
                    if getattr(ex, "errno", None) == getattr(os, "EXDEV", 18):
                        import shutil
                        import tempfile as _tempfile

                        with open(self.path, "rb") as src, _tempfile.NamedTemporaryFile(
                            "wb", delete=False, dir=str(dst.parent)
                        ) as tmp:
                            shutil.copyfileobj(src, tmp)
                            tmp.flush()
                            try:
                                os.fsync(tmp.fileno())
                            except Exception as exc:
                                log_best_effort(__name__, exc)
                            tmp_path = Path(tmp.name)
                        try:
                            os.replace(tmp_path, dst)
                            self._finalized = True
                            try:
                                dir_flag = getattr(os, "O_DIRECTORY", None)
                                if dir_flag is not None:
                                    dir_fd = os.open(str(dst.parent), dir_flag)
                                    try:
                                        os.fsync(dir_fd)
                                    finally:
                                        os.close(dir_fd)
                            except Exception as exc:
                                log_best_effort(__name__, exc)
                            return
                        finally:
                            try:
                                os.remove(self.path)
                            except Exception as exc:
                                log_best_effort(__name__, exc)
                    else:
                        raise
            os.replace(self.path, dst)
            self._finalized = True
            try:
                dir_flag = getattr(os, "O_DIRECTORY", None)
                if dir_flag is not None:
                    dir_fd = os.open(str(dst.parent), dir_flag)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
            except Exception as exc:
                log_best_effort(__name__, exc)
        finally:
            # ensure temp is removed if finalize fails mid-way
            if not self._finalized and self.path.exists():
                try:
                    os.remove(self.path)
                except Exception as exc:
                    log_best_effort(__name__, exc)

    def close(self):
        try:
            self._file.close()
        except Exception as exc:
            log_best_effort(__name__, exc)
        if not self._finalized and self.path.exists():
            try:
                os.remove(self.path)
            except Exception as exc:
                log_best_effort(__name__, exc)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
