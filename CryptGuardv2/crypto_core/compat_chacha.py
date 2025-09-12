"""
Legacy fallback for XChaCha20-Poly1305 (deprecated).

This module is kept as a stub to avoid hard import errors in legacy code paths.
SecretStream (v5) requires PyNaCl/libsodium. For legacy v1–v4 XChaCha, install
PyNaCl or a cryptography build with XChaCha20-Poly1305 support.
"""

class ChaCha20_Poly1305:  # pragma: no cover - legacy stub only
    @staticmethod
    def new(*args, **kwargs):
        raise RuntimeError("compat_chacha backend removed; install PyNaCl for XChaCha20 support")

