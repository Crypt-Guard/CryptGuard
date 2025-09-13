# secure_bytes.py
"""Secure bytes container with guaranteed memory cleanup and optional memory locking."""
from __future__ import annotations

import ctypes
import platform
import sys
import threading
import warnings
import weakref
from importlib import util as _imp_util
from typing import Callable, Optional, Union, Final

# Type alias for byte-like objects
BytesLike = Union[bytes, bytearray, memoryview]

# Constants
MIN_LOCK_SIZE: Final[int] = 4096  # Minimum size to attempt memory locking
_HAVE_SODIUM: Final[bool] = _imp_util.find_spec("nacl") is not None


def secure_memzero(buf: bytearray) -> None:
    """
    Zero memory buffer in a way that resists compiler optimization.
    
    Tries in order:
    1. Windows: RtlSecureZeroMemory (guaranteed no optimization)
    2. POSIX: explicit_bzero when available
    3. Generic: ctypes.memset with compiler barrier
    4. Fallback: manual loop with volatile-like access pattern
    
    Args:
        buf: Buffer to zero. Safe to pass empty buffer.
    """
    if not buf:
        return
    
    n = len(buf)
    
    try:
        # Prefer libsodium's sodium_memzero when available
        if _HAVE_SODIUM:
            try:
                import nacl.bindings as _sod  # type: ignore
                # sodium_memzero expects (void*, size_t)
                addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
                _sod.sodium_memzero(ctypes.c_void_p(addr), ctypes.c_size_t(len(buf)))
                return
            except Exception:
                pass

        # Get buffer address for ctypes operations
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
        
        # Windows: RtlSecureZeroMemory
        if platform.system() == "Windows":
            try:
                kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                rtl_zero = kernel32.RtlSecureZeroMemory
                rtl_zero.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
                rtl_zero.restype = ctypes.c_void_p
                rtl_zero(addr, n)
                return
            except (AttributeError, OSError):
                pass  # Fall through to next method
        
        # Linux/BSD: explicit_bzero
        if hasattr(ctypes, "CDLL"):
            for lib_name in ("libc.so.6", "libc.so.7", "libc.dylib", "libSystem.dylib"):
                try:
                    libc = ctypes.CDLL(lib_name)
                    if hasattr(libc, "explicit_bzero"):
                        libc.explicit_bzero.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
                        libc.explicit_bzero.restype = None
                        libc.explicit_bzero(addr, n)
                        return
                except (OSError, AttributeError):
                    continue
        
        # Generic: memset with attempt at compiler barrier
        ctypes.memset(addr, 0, n)
        
        # Try to prevent optimization by accessing Python internals
        # This creates a side effect that may prevent dead store elimination
        try:
            _ = ctypes.c_int.in_dll(ctypes.pythonapi, "Py_OptimizeFlag")
        except (AttributeError, ValueError):
            pass
            
    except Exception:
        pass  # Fall through to manual zeroing
    
    # Last resort: manual zeroing with forced memory access
    for i in range(n):
        buf[i] = 0
        # Force memory access to prevent optimization
        _ = buf[i]


def try_lock_memory(buf: bytearray) -> bool:
    """
    Attempt to lock memory pages to prevent swapping.
    
    Args:
        buf: Buffer to lock in memory
        
    Returns:
        True if successfully locked, False otherwise
    """
    if not buf or len(buf) < MIN_LOCK_SIZE:
        return False
    
    try:
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
        size = len(buf)
        
        if platform.system() == "Windows":
            try:
                kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                # Attempt to increase working set to accommodate the lock
                try:
                    GetCurrentProcess = kernel32.GetCurrentProcess
                    GetProcessWorkingSetSize = kernel32.GetProcessWorkingSetSize
                    SetProcessWorkingSetSize = kernel32.SetProcessWorkingSetSize
                    min_ws = ctypes.c_size_t()
                    max_ws = ctypes.c_size_t()
                    GetProcessWorkingSetSize(GetCurrentProcess(), ctypes.byref(min_ws), ctypes.byref(max_ws))
                    new_min = ctypes.c_size_t(min_ws.value + size)
                    new_max = ctypes.c_size_t(max_ws.value + size)
                    SetProcessWorkingSetSize(GetCurrentProcess(), new_min, new_max)
                except Exception:
                    pass
                # VirtualLock returns non-zero on success
                result = kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
                return bool(result)
            except (AttributeError, OSError):
                return False
        else:
            # POSIX systems: try mlock
            for lib_name in ("libc.so.6", "libc.so.7", "libc.dylib", "libSystem.dylib"):
                try:
                    libc = ctypes.CDLL(lib_name)
                    if hasattr(libc, "mlock"):
                        libc.mlock.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
                        libc.mlock.restype = ctypes.c_int
                        # mlock returns 0 on success
                        result = libc.mlock(addr, size)
                        return result == 0
                except (OSError, AttributeError):
                    continue
    except Exception:
        pass
    
    return False


def try_unlock_memory(buf: bytearray) -> bool:
    """
    Attempt to unlock previously locked memory pages.
    
    Args:
        buf: Buffer to unlock
        
    Returns:
        True if successfully unlocked, False otherwise
    """
    if not buf:
        return False
    
    try:
        # Prefer sodium_munlock when available
        if _HAVE_SODIUM:
            try:
                import nacl.bindings as _sod  # type: ignore
                addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
                _sod.sodium_munlock(ctypes.c_void_p(addr), ctypes.c_size_t(len(buf)))
                return True
            except Exception:
                pass

        addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
        size = len(buf)
        
        if platform.system() == "Windows":
            try:
                kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                result = kernel32.VirtualUnlock(ctypes.c_void_p(addr), ctypes.c_size_t(size))
                return bool(result)
            except (AttributeError, OSError):
                return False
        else:
            # POSIX systems: try munlock
            for lib_name in ("libc.so.6", "libc.so.7", "libc.dylib", "libSystem.dylib"):
                try:
                    libc = ctypes.CDLL(lib_name)
                    if hasattr(libc, "munlock"):
                        libc.munlock.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
                        libc.munlock.restype = ctypes.c_int
                        result = libc.munlock(addr, size)
                        return result == 0
                except (OSError, AttributeError):
                    continue
    except Exception:
        pass
    
    return False


class SecureBytes:
    """
    Secure container for sensitive byte data with guaranteed cleanup.
    
    Features:
    - Internal mutable buffer (bytearray) for secure zeroing
    - Optional memory locking to prevent swap (best-effort)
    - Thread-safe operations with RLock
    - Context manager support for automatic cleanup
    - No information leakage through repr/str
    
    Usage:
        # Basic usage
        sb = SecureBytes(b"secret_key")
        view = sb.view()  # Get read-only view without copy
        sb.clear()  # Securely zero the memory
        
        # With context manager
        with SecureBytes(b"temporary_secret") as sb:
            view = sb.view()
            # Use the secret
        # Automatically cleared when exiting context
        
        # Callback pattern for temporary access
        sb.with_bytes(lambda b: process(b))
    """
    
    __slots__ = ("_buf", "_cleared", "_locked", "_lock", "_finalizer", "__weakref__")
    
    def __init__(self, data: BytesLike, *, lock_memory: bool = True) -> None:
        """
        Initialize SecureBytes with sensitive data.
        
        Args:
            data: Bytes to protect. Must not be empty.
            lock_memory: Whether to attempt locking pages in memory.
            
        Raises:
            TypeError: If data is not bytes/bytearray/memoryview
            ValueError: If data is empty
        """
        # Convert input to bytes
        if isinstance(data, memoryview):
            if data.c_contiguous:
                data = data.tobytes()
            else:
                data = bytes(data)
        elif isinstance(data, bytearray):
            # Make a copy to avoid external aliasing
            data = bytes(data)
        elif not isinstance(data, bytes):
            raise TypeError(f"SecureBytes requires bytes/bytearray/memoryview, got {type(data).__name__}")
        
        if len(data) == 0:
            raise ValueError("SecureBytes cannot be empty")
        
        # Initialize state
        self._buf = bytearray(data)
        self._cleared = False
        self._locked = False
        self._lock = threading.RLock()
        # Ensure cleanup even if GC'd without context manager
        self._finalizer = weakref.finalize(self, self.clear)
        
        # Attempt to lock memory if requested
        if lock_memory and len(self._buf) >= MIN_LOCK_SIZE:
            # Prefer sodium_mlock when available
            ok = False
            if _HAVE_SODIUM:
                try:
                    import nacl.bindings as _sod  # type: ignore
                    addr = ctypes.addressof(ctypes.c_char.from_buffer(self._buf))
                    _sod.sodium_mlock(ctypes.c_void_p(addr), ctypes.c_size_t(len(self._buf)))
                    ok = True
                except Exception:
                    ok = False
            if not ok:
                self._locked = try_lock_memory(self._buf)
            else:
                self._locked = True
            if not self._locked:
                warnings.warn(
                    f"Failed to lock {len(self._buf)} bytes in memory; data may be swapped to disk",
                    stacklevel=2,
                )
    
    def view(self) -> memoryview:
        """
        Get a read-only memory view of the data without copying.

        Returns:
            Read-only memoryview of the internal buffer.

        Raises:
            ValueError: If already cleared
        """
        with self._lock:
            if self._cleared:
                raise ValueError("SecureBytes already cleared")
            mv = memoryview(self._buf)
            try:
                return mv.toreadonly()
            except Exception:
                # Fallback: copy to immutable bytes then memoryview
                return memoryview(bytes(self._buf))
    
    def with_bytes(self, callback: Callable[[bytes], None]) -> None:
        """
        Execute callback with a temporary bytes copy.
        Best-effort cleanup releases the reference immediately after use.
        
        Args:
            callback: Function to call with bytes copy
        
        Raises:
            ValueError: If already cleared
        """
        with self._lock:
            if self._cleared:
                raise ValueError("SecureBytes already cleared")
            
            # Create temporary copy for the callback
            temp = bytes(self._buf)
            try:
                callback(temp)
            finally:
                # Bytes are immutable; we cannot securely zero them.
                # Drop the reference as soon as possible.
                try:
                    del temp
                except Exception:
                    pass
    
    def to_bytes(self) -> bytes:
        """
        DEPRECATED: Get a copy of the bytes.
        
        Warning: This creates a copy that won't be securely cleared.
        Use view() or with_bytes() instead.
        
        Returns:
            Copy of the internal bytes
            
        Raises:
            ValueError: If already cleared
        """
        warnings.warn(
            "to_bytes() creates an insecure copy. Use view() or with_bytes() instead.",
            DeprecationWarning,
            stacklevel=2
        )
        with self._lock:
            if self._cleared:
                raise ValueError("SecureBytes already cleared")
            return bytes(self._buf)
    
    def clear(self) -> None:
        """
        Securely zero the internal buffer and mark as cleared.
        
        This method is idempotent - calling it multiple times is safe.
        If memory was locked, attempts to unlock it.
        """
        with self._lock:
            if not self._cleared:
                # Zero the buffer
                secure_memzero(self._buf)
                
                # Unlock memory if it was locked
                if self._locked:
                    try_unlock_memory(self._buf)
                    self._locked = False
                
                # Clear the buffer and mark as cleared
                self._buf.clear()
                self._cleared = True
    
    @property
    def cleared(self) -> bool:
        """Check if the bytes have been cleared."""
        with self._lock:
            return self._cleared
    
    def __enter__(self) -> SecureBytes:
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type: type, exc_val: Exception, exc_tb: object) -> None:
        """Context manager exit - ensures cleanup."""
        self.clear()
    
    def __del__(self) -> None:
        """Destructor - ensures cleanup even if not explicitly cleared."""
        try:
            self.clear()
        except Exception:
            pass  # Best effort in destructor
    
    def __len__(self) -> int:
        """Get length of data, or 0 if cleared."""
        with self._lock:
            return 0 if self._cleared else len(self._buf)
    
    def __repr__(self) -> str:
        """Safe representation that doesn't leak information."""
        return "<SecureBytes ***>"
    
    def __str__(self) -> str:
        """Safe string representation that doesn't leak information."""
        return "<SecureBytes ***>"


# Export public API
__all__ = ["SecureBytes", "secure_memzero", "try_lock_memory", "try_unlock_memory"]
