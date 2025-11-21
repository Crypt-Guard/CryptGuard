from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
import sys
import threading
from contextlib import contextmanager, suppress
from typing import Any

from crypto_core.logger import logger as _project_logger

_log = _project_logger

_SODIUM: ctypes.CDLL | None = None
_SODIUM_INIT_ATTEMPTED = False
_INFO_LOGGED = False
_WARN_LOGGED = False
_INIT_LOCK = threading.Lock()

HAVE_SODIUM = False
DEFAULT_STRICT = os.getenv("CG_SECUREMEM_STRICT", "0") == "1"


def _win_is_64bit() -> bool:
    """Verifica se o Windows é 64-bit."""
    return platform.machine().lower() in ("amd64", "x86_64")


def _vendor_dir_windows() -> str | None:
    """
    Retorna o caminho do diretório vendorizado do libsodium para Windows,
    ou None se não existir.
    """
    try:
        # Tenta usar importlib.resources (Python 3.9+)
        try:
            import importlib.resources as pkg_resources
            # Obtém o pacote raiz (crypto_core -> CryptGuardv2)
            base = pkg_resources.files(__package__.split('.')[0] if __package__ else 'crypto_core')
            if hasattr(base, 'parent'):
                base = base.parent
            base = str(base)
        except Exception:
            # Fallback: caminho relativo ao arquivo atual
            # crypto_core/securemem.py -> crypto_core -> raiz do projeto
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Estrutura real: vendor/WINDOWS/x64/v1.0.20-v143/libsodium.dll
        vend = os.path.join(base, "vendor", "WINDOWS", "x64", "v1.0.20-v143")
        return vend if os.path.isdir(vend) else None
    except Exception as e:
        _log.debug("securemem: erro ao localizar diretório vendorizado: %s", e)
        return None


def _load_libsodium() -> ctypes.CDLL:
    """
    Carrega a biblioteca libsodium com suporte aprimorado para Windows.
    
    Ordem de priorização:
    1) SODIUM_DLL_DIR (env var do admin)
    2) Diretório vendorizado do projeto (vendor/WINDOWS/x64/v1.0.20-v143)
    3) ctypes.util.find_library('sodium') - fallback padrão
    
    Usa os.add_dll_directory() (Python 3.8+) para registrar diretórios de DLL.
    """
    # 1) Windows com add_dll_directory (Python 3.8+)
    if sys.platform == "win32":
        if not _win_is_64bit():
            raise OSError("libsodium: apenas x64 suportado neste build")

        dirs_to_try: list[str] = []
        
        # Prioridade 1: variável de ambiente do admin
        env_dir = os.environ.get("SODIUM_DLL_DIR")
        if env_dir:
            dirs_to_try.append(env_dir)
        
        # Prioridade 2: diretório vendorizado do projeto
        vend = _vendor_dir_windows()
        if vend:
            dirs_to_try.append(vend)

        # Tenta carregar de cada diretório registrado
        for d in dirs_to_try:
            try:
                os.add_dll_directory(d)  # requer Py3.8+
                _log.debug("securemem: added DLL dir: %s", d)
                return ctypes.CDLL("libsodium.dll")
            except Exception as e:
                _log.warning("securemem: fail load from %s: %r", d, e)

        # Prioridade 3: Fallback - use heurística do ctypes
        name = ctypes.util.find_library("sodium") or "libsodium.dll"
        return ctypes.CDLL(name)

    # 2) Outros SOs: tente o nome padrão/ldconfig
    name = ctypes.util.find_library("sodium") or "libsodium"
    return ctypes.CDLL(name)


def _load_sodium() -> None:
    global _SODIUM, HAVE_SODIUM, _SODIUM_INIT_ATTEMPTED
    if HAVE_SODIUM or _SODIUM_INIT_ATTEMPTED:
        return
    with _INIT_LOCK:
        if HAVE_SODIUM or _SODIUM_INIT_ATTEMPTED:
            return
        _SODIUM_INIT_ATTEMPTED = True
        
        # Tenta carregar usando o novo método aprimorado
        try:
            lib = _load_libsodium()
        except Exception as e:
            _log.debug("securemem: falha ao carregar libsodium via _load_libsodium: %s", e)
            lib = None
        
        # Se falhou, tenta os candidatos tradicionais
        if lib is None:
            lib_name = ctypes.util.find_library("sodium")
            candidates: list[str] = []
            if lib_name:
                candidates.append(lib_name)
            candidates.extend(["libsodium", "sodium"])
            
            for name in candidates:
                try:
                    lib = ctypes.CDLL(name)
                    break
                except Exception:
                    continue
        
        # Se conseguiu carregar, tenta inicializar
        if lib is not None:
            try:
                lib.sodium_init.restype = ctypes.c_int
                if lib.sodium_init() < 0:
                    _log.debug("securemem: sodium_init() retornou erro")
                    return
                lib.sodium_mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                lib.sodium_mlock.restype = ctypes.c_int
                lib.sodium_munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                lib.sodium_munlock.restype = ctypes.c_int
                lib.sodium_memzero.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                lib.sodium_memzero.restype = None
                
                _SODIUM = lib
                HAVE_SODIUM = True
            except Exception as e:
                _log.debug("securemem: falha ao configurar funções do libsodium: %s", e)


def ensure_securemem_ready(strict: bool) -> None:
    """
    Ensure libsodium-backed secure memory is ready.
    When strict=True and libsodium is unavailable, raise RuntimeError.
    """
    global _INFO_LOGGED, _WARN_LOGGED
    _load_sodium()
    if HAVE_SODIUM:
        if not _INFO_LOGGED:
            _log.info("securemem: libsodium enabled")
            _INFO_LOGGED = True
        return

    if strict:
        _log.error("securemem: libsodium ausente; instale libsodium-dev / libsodium")
        raise RuntimeError("libsodium ausente; instale libsodium-dev / libsodium")

    if not _WARN_LOGGED:
        _log.warning("securemem: downgraded (no libsodium)")
        _WARN_LOGGED = True


def _zero_python_buffer(buf: bytearray | memoryview) -> None:
    if isinstance(buf, memoryview):
        if buf.readonly:
            raise TypeError("Buffer is read-only")
        buf[:] = b"\x00" * len(buf)
        buf.release()
    else:
        buf[:] = b"\x00" * len(buf)


def wipe(buf: Any) -> None:
    """
    Best-effort zeroization for arbitrary mutable buffers.
    Uses libsodium when available, falling back to Python-level writes.
    """
    try:
        mv = memoryview(buf)
    except TypeError as exc:
        raise TypeError("Object does not expose a writable buffer") from exc

    try:
        if mv.readonly:
            raise TypeError("Buffer is read-only; provide a mutable buffer")
        if HAVE_SODIUM and _SODIUM is not None:
            try:
                ptr = ctypes.addressof(ctypes.c_char.from_buffer(mv))
            except (TypeError, BufferError):
                _zero_python_buffer(mv)
            else:
                _SODIUM.sodium_memzero(ctypes.c_void_p(ptr), ctypes.c_size_t(mv.nbytes))
                mv.release()
        else:
            _zero_python_buffer(mv)
    finally:
        with suppress(Exception):
            mv.release()


class LockedBuf:
    """
    Secure buffer abstraction that locks memory via libsodium when available.
    Falls back to a Python bytearray only when libsodium is unavailable and strict mode is off.
    """

    __slots__ = ("_size", "_ptr", "_buf", "_fallback", "_closed")

    def __init__(self, size: int, *, strict: bool | None = None):
        size = int(size)
        if size <= 0:
            raise ValueError("size must be > 0")
        if strict is None:
            strict = DEFAULT_STRICT
        ensure_securemem_ready(strict=strict)

        self._size = size
        self._ptr: int | None = None
        self._buf: ctypes.Array | None = None
        self._fallback: bytearray | None = None
        self._closed = False
        if HAVE_SODIUM and _SODIUM is not None:
            try:
                buf = ctypes.create_string_buffer(self._size)
                addr = ctypes.addressof(buf)
                rc = _SODIUM.sodium_mlock(ctypes.c_void_p(addr), ctypes.c_size_t(self._size))
                if rc != 0:
                    raise OSError("sodium_mlock failed")
            except Exception:
                raise RuntimeError("Falha ao alocar memória segura com libsodium")
            self._buf = buf
            self._ptr = addr
        else:
            self._fallback = bytearray(self._size)

    @property
    def size(self) -> int:
        return self._size

    def mv(self) -> memoryview:
        if self._closed:
            raise RuntimeError("LockedBuf já foi fechado")
        if HAVE_SODIUM and self._buf is not None and self._ptr is not None:
            typ = ctypes.c_ubyte * self._size
            arr = typ.from_address(self._ptr)
            return memoryview(arr)
        if self._fallback is None:
            raise RuntimeError("LockedBuf fallback buffer indisponível")
        return memoryview(self._fallback)

    def wipe(self) -> None:
        if self._closed:
            return
        if HAVE_SODIUM and self._ptr is not None and _SODIUM is not None:
            _SODIUM.sodium_memzero(
                ctypes.c_void_p(self._ptr),
                ctypes.c_size_t(self._size),
            )
        elif self._fallback is not None:
            self._fallback[:] = b"\x00" * len(self._fallback)

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.wipe()
        finally:
            if HAVE_SODIUM and self._ptr is not None and _SODIUM is not None:
                _SODIUM.sodium_munlock(
                    ctypes.c_void_p(self._ptr),
                    ctypes.c_size_t(self._size),
                )
            self._buf = None
            self._fallback = None
            self._ptr = None
            self._closed = True

    # Compatibility no-ops
    def protect(self) -> None:  # pragma: no cover - compatibility
        return

    def unprotect(self) -> None:  # pragma: no cover - compatibility
        return

    def __enter__(self) -> LockedBuf:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()


@contextmanager
def secret_bytes(initial: bytes | None = None, size: int | None = None, *, strict: bool | None = None):
    """
    Context manager yielding a RW memoryview that is zeroized and unlocked upon exit.
    """
    if initial is None and size is None:
        raise ValueError("provide initial or size")
    length = len(initial) if initial is not None else int(size)  # type: ignore[arg-type]
    buf = LockedBuf(length, strict=strict)
    try:
        mv = buf.mv()
        if initial is not None:
            # Copy initial bytes (Python 3.13 compat: use ctypes)
            import ctypes
            if hasattr(mv, 'obj') and isinstance(mv.obj, ctypes.Array):
                # Direct ctypes array access
                for idx, byte in enumerate(initial):
                    mv.obj[idx] = byte
            else:
                # Fallback: convert to bytes and back
                temp = bytearray(mv)
                temp[:len(initial)] = initial
                for idx in range(len(initial)):
                    mv[idx] = temp[idx]
        yield mv
    finally:
        buf.close()


__all__ = [
    "HAVE_SODIUM",
    "DEFAULT_STRICT",
    "ensure_securemem_ready",
    "LockedBuf",
    "secret_bytes",
    "wipe",
]
