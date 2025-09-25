from __future__ import annotations

import ctypes
import logging
from contextlib import contextmanager, suppress

_log = logging.getLogger(__name__)
_warned_fallback = False


class LockedBuf:
    """
    Best-effort locked buffer using libsodium if available.
    - Allocates via sodium_malloc (guard pages) when possible
    - mlock to avoid swap
    - mprotect NOACCESS when protected
    Fallback: bytearray with zeroization on wipe().
    """

    __slots__ = ("_ptr", "_size", "_buf", "_lib", "_ro", "_protected")

    def __init__(self, size: int):
        if int(size) <= 0:
            raise ValueError("size must be > 0")
        self._ptr = None
        self._size = int(size)
        self._buf = None
        self._lib = None
        self._ro = False
        self._protected = False

        global _warned_fallback
        used_fallback = False

        # Try libsodium first
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
            with suppress(Exception):
                self._lib.sodium_mlock(ptr, self._size)
                self._lib.sodium_mprotect_readwrite(ptr)
            # Successfully initialized with libsodium
        except Exception:
            # Fallback: Python bytearray that we zero manually
            self._lib = None
            self._ptr = None
            used_fallback = True

        if used_fallback and not _warned_fallback:
            _log.warning(
                "Secure memory downgraded: libsodium not available; falling back to Python bytearray."
            )
            _warned_fallback = True

        # Ensure we always have a fallback buffer if libsodium failed
        if self._lib is None or self._ptr is None:
            self._buf = bytearray(self._size)
            self._lib = None
            self._ptr = None
            used_fallback = True

    @property
    def size(self) -> int:
        return self._size

    def mv(self) -> memoryview:
        """Return uma janela 1-D de bytes sem sinal, apta a mv[:] = b"..."."""
        if self._ro:
            raise RuntimeError(
                "LockedBuf is protected (NOACCESS); acquire within an unprotected context"
            )
        if self._lib and self._ptr:
            typ = ctypes.c_ubyte * self._size
            arr = typ.from_address(self._ptr)
            base = memoryview(arr)
        else:
            if self._buf is None:
                # fallback must exist; otherwise it is an initialization bug
                raise RuntimeError("LockedBuf not initialized (no ptr and no fallback buffer)")
            base = memoryview(self._buf)
        try:
            mv = base.cast("B", shape=(base.nbytes,))
        except TypeError:
            mv = base.cast("B")
        return mv

    def protect(self):
        if self._lib and self._ptr and not self._ro:
            with suppress(Exception):
                self._lib.sodium_mprotect_noaccess(self._ptr)
                self._ro = True
                self._protected = True

    def unprotect(self):
        if self._lib and self._ptr and self._ro:
            with suppress(Exception):
                self._lib.sodium_mprotect_readwrite(self._ptr)
                self._ro = False
                self._protected = False

    def wipe(self):
        try:
            if self._lib and self._ptr:
                # ensure RW before wiping/unlocking
                with suppress(Exception):
                    self._lib.sodium_mprotect_readwrite(self._ptr)
                    # refletir estado RW internamente
                    self._ro = False
                    self._protected = False
                # zero memory via ctypes.memset
                try:
                    # declare ctypes prototypes for memset to be robust
                    ctypes.memset.restype = ctypes.c_void_p
                    ctypes.memset.argtypes = (
                        ctypes.c_void_p,
                        ctypes.c_int,
                        ctypes.c_size_t,
                    )
                    ctypes.memset(self._ptr, 0, self._size)
                except Exception:
                    # fallback to memoryview write
                    with suppress(Exception):
                        mv = self.mv()
                        mv[:] = b"\x00" * self._size
                        with suppress(Exception):
                            mv.release()
                # unlock and free
                with suppress(Exception):
                    self._lib.sodium_munlock(self._ptr, self._size)
                with suppress(Exception):
                    self._lib.sodium_free(self._ptr)
                # replenish fallback buffer for post-wipe inspection
                self._buf = bytearray(self._size)
                self._ptr = None
                self._lib = None
            elif self._buf is not None:
                with suppress(Exception):
                    mv = memoryview(self._buf).cast("B")
                    mv[:] = b"\x00" * self._size
                    with suppress(Exception):
                        mv.release()
                if self._buf is not None:
                    with suppress(Exception):
                        for i in range(len(self._buf)):
                            self._buf[i] = 0
        finally:
            # Clean up libsodium resources
            if self._lib and self._ptr:
                self._ptr = None
                self._lib = None
            # For fallback buffer, zero and recreate instead of destroying
            elif self._buf is not None:
                # Zero the buffer securely before recreating
                with suppress(Exception):
                    for i in range(len(self._buf)):
                        self._buf[i] = 0
                # Recreate the buffer for potential reuse
                self._buf = bytearray(self._size)
            else:
                # Neither libsodium nor fallback buffer - just ensure clean state
                self._ptr = None
                self._buf = None

    def __enter__(self):
        self.unprotect()
        return self

    def __exit__(self, *exc):
        self.protect()

    def __del__(self):
        with suppress(Exception):
            self.wipe()


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
