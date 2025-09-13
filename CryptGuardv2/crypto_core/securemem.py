from __future__ import annotations

import ctypes
from contextlib import contextmanager


class LockedBuf:
    """
    Best-effort locked buffer using libsodium if available.
    - Allocates via sodium_malloc (guard pages) when possible
    - mlock to avoid swap
    - mprotect NOACCESS when protected
    Fallback: bytearray with zeroization on wipe().
    """

    __slots__ = ("_ptr", "_size", "_buf", "_lib", "_ro")

    def __init__(self, size: int):
        self._ptr = None
        self._size = int(size)
        self._buf = None
        self._ro = True
        try:
            self._lib = ctypes.CDLL("libsodium")
            if self._lib.sodium_init() < 0:
                raise OSError("sodium_init failed")
            self._lib.sodium_malloc.restype = ctypes.c_void_p
            self._lib.sodium_free.argtypes = [ctypes.c_void_p]
            self._lib.sodium_mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            self._lib.sodium_munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            self._lib.sodium_mprotect_noaccess.argtypes = [ctypes.c_void_p]
            self._lib.sodium_mprotect_readwrite.argtypes = [ctypes.c_void_p]

            ptr = self._lib.sodium_malloc(self._size)
            if not ptr:
                raise MemoryError("sodium_malloc returned NULL")
            self._ptr = ptr
            # best-effort lock and set RW
            try:
                self._lib.sodium_mlock(ptr, self._size)
                self._lib.sodium_mprotect_readwrite(ptr)
            except Exception:
                pass
            self._ro = False
        except Exception:
            self._lib = None
            self._buf = bytearray(self._size)
            self._ptr = None
            self._ro = False

    @property
    def size(self) -> int:
        return self._size

    def mv(self) -> memoryview:
        """Return a mutable memoryview without copying."""
        if self._lib and self._ptr:
            typ = ctypes.c_ubyte * self._size
            arr = typ.from_address(self._ptr)
            return memoryview(arr)
        return memoryview(self._buf)  # type: ignore[arg-type]

    def protect(self):
        if self._lib and self._ptr and not self._ro:
            try:
                self._lib.sodium_mprotect_noaccess(self._ptr)
                self._ro = True
            except Exception:
                pass

    def unprotect(self):
        if self._lib and self._ptr and self._ro:
            try:
                self._lib.sodium_mprotect_readwrite(self._ptr)
                self._ro = False
            except Exception:
                pass

    def wipe(self):
        try:
            mv = self.mv()
            mv[:] = b"\x00" * self._size
            try:
                mv.release()
            except Exception:
                pass
        except Exception:
            pass
        if self._lib and self._ptr:
            try:
                self._lib.sodium_munlock(self._ptr, self._size)
            except Exception:
                pass
            try:
                self._lib.sodium_free(self._ptr)
            except Exception:
                pass
        self._ptr = None
        self._buf = None

    def __enter__(self):
        self.unprotect()
        return self

    def __exit__(self, *exc):
        self.protect()

    def __del__(self):
        try:
            self.wipe()
        except Exception:
            pass


@contextmanager
def secret_bytes(initial: bytes | None = None, size: int | None = None):
    """
    Context: yields a RW memoryview that is zeroized and freed upon exit.
    """
    if initial is None and size is None:
        raise ValueError("provide initial or size")
    s = len(initial) if initial is not None else int(size)  # type: ignore[arg-type]
    lb = LockedBuf(s)
    try:
        lb.unprotect()
        mv = lb.mv()
        if initial is not None:
            mv[: len(initial)] = initial
        yield mv
    finally:
        lb.wipe()

