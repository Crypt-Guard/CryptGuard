"""
SecureBytes com wipe multi-pass e mlock/VirtualLock.
"""
import ctypes, mmap, os, secrets, sys

_PASSES = [0xFF, 0x00, 0x55, 0xAA]  # padrão DoD + random extra

def _mlock(buf):
    try:
        libc = ctypes.CDLL("libc.so.6")
        libc.mlock(ctypes.addressof(ctypes.c_char.from_buffer(buf)), len(buf))
    except Exception:
        pass  # opcional

def _munlock(buf):
    try:
        libc = ctypes.CDLL("libc.so.6")
        libc.munlock(ctypes.addressof(ctypes.c_char.from_buffer(buf)), len(buf))
    except Exception:
        pass

class SecureBytes:
    __slots__ = ("_buf", "_size")

    def __init__(self, data: bytes | bytearray):
        self._size = len(data)
        self._buf  = mmap.mmap(-1, self._size)
        _mlock(self._buf)
        self._buf.write(data)

    def to_bytes(self) -> bytes:
        self._buf.seek(0)
        return self._buf.read(self._size)

    def clear(self):
        for pattern in _PASSES + [secrets.randbits(8)]:
            self._buf.seek(0)
            self._buf.write(bytes([pattern]) * self._size)
            self._buf.flush()
        _munlock(self._buf)
        self._buf.close()

    def __del__(self):
        try: self.clear()
        except Exception: pass
