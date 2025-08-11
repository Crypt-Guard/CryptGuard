"""
SecureBytes com wipe multi-pass e mlock/VirtualLock.
"""
import mmap, secrets, ctypes, platform   # atualização de imports
from ctypes.util import find_library     # add robust libc discovery

_PASSES = [0xFF, 0x00, 0x55, 0xAA]  # padrão DoD + random extra

# cache libc handle
_LIBC = None

def _libc():
    """Resolve libc cross-platform with caching and fallbacks."""
    global _LIBC
    if _LIBC:
        return _LIBC
    try:
        if platform.system() == "Darwin":
            name = "libSystem.B.dylib"
        else:
            name = find_library("c") or "libc.so.6"
        _LIBC = ctypes.CDLL(name)
    except Exception:
        # last resort: try default process
        _LIBC = ctypes.CDLL(None)
    return _LIBC

def _addr(buf) -> int:
    """Get base address of the mmap buffer."""
    return ctypes.addressof(ctypes.c_char.from_buffer(buf))

def memset(ptr, value, size):
    """Cross-platform memset implementation with proper prototypes"""
    try:
        if platform.system() == "Windows":
            fn = ctypes.windll.msvcrt.memset
        else:
            fn = _libc().memset
        # set signatures
        fn.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
        fn.restype  = ctypes.c_void_p
        fn(ctypes.c_void_p(ptr), ctypes.c_int(value), ctypes.c_size_t(size))
    except Exception:
        pass

def _mlock(buf):
    try:
        if platform.system() == "Windows":
            k32 = ctypes.windll.kernel32
            k32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            k32.VirtualLock.restype  = ctypes.c_int
            k32.VirtualLock(ctypes.c_void_p(_addr(buf)), ctypes.c_size_t(len(buf)))
        else:
            libc = _libc()
            libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libc.mlock.restype  = ctypes.c_int
            libc.mlock(ctypes.c_void_p(_addr(buf)), ctypes.c_size_t(len(buf)))
    except Exception:
        pass

def _munlock(buf):
    try:
        if platform.system() == "Windows":
            k32 = ctypes.windll.kernel32
            k32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            k32.VirtualUnlock.restype  = ctypes.c_int
            k32.VirtualUnlock(ctypes.c_void_p(_addr(buf)), ctypes.c_size_t(len(buf)))
        else:
            libc = _libc()
            libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libc.munlock.restype  = ctypes.c_int
            libc.munlock(ctypes.c_void_p(_addr(buf)), ctypes.c_size_t(len(buf)))
    except Exception:
        pass

class SecureBytes:
    __slots__ = ("_buf", "_size", "_closed")  # adiciona flag de estado

    def __init__(self, data: bytes | bytearray):
        if len(data) == 0:
            raise ValueError("SecureBytes cannot be empty")
        self._size   = len(data)
        self._buf    = mmap.mmap(-1, self._size)
        self._closed = False                     # inicializa flag
        _mlock(self._buf)
        self._buf.write(data)
        # reduzir vida útil do plaintext de origem quando possível
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0

    def to_bytes(self) -> bytes:
        if self._closed:
            raise ValueError("SecureBytes already cleared")
        self._buf.seek(0)
        return self._buf.read(self._size)

    def clear(self):
        if self._closed:                          # idempotência
            return
        try:
            ptr = _addr(self._buf)
            for patt in _PASSES + [secrets.randbits(8)]:
                memset(ptr, patt, self._size)
                try:
                    self._buf.flush()
                except Exception:
                    pass
            _munlock(self._buf)
            self._buf.close()
        finally:
            self._closed = True                  # marca como já limpo
            # prevent accidental reuse
            self._buf = None
            self._size = 0

    def __enter__(self):
        if self._closed:
            raise ValueError("SecureBytes already cleared")
        return self

    def __exit__(self, exc_type, exc, tb):
        self.clear()

    def __del__(self):
        try: self.clear()
        except Exception: pass
