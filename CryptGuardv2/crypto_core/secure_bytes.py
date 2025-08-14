# crypto_core/secure_bytes.py
from __future__ import annotations

import ctypes
from typing import Union

BytesLike = Union[bytes, bytearray, memoryview]


def _secure_memzero(buf: bytearray) -> None:
    """
    Zera o conteúdo de um bytearray de forma mais confiável possível:
    - Tenta usar a API do Windows (RtlSecureZeroMemory) se disponível;
    - Caso contrário, cai para ctypes.memset;
    - Em último caso, zera por loop.
    """
    if not buf:
        return
    n = len(buf)
    try:
        # Endereço do buffer subjacente
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
        # Windows: RtlSecureZeroMemory (se existir)
        try:
            _rtl = ctypes.windll.kernel32.RtlSecureZeroMemory  # type: ignore[attr-defined]
            _rtl.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
            _rtl.restype = ctypes.c_void_p
            _rtl(addr, n)
            return
        except Exception:
            pass  # nosec B110 (fallback intencional; caminho alternativo abaixo)
        # Fallback genérico
        ctypes.memset(addr, 0, n)
    except Exception:
        # Último recurso
        for i in range(n):
            buf[i] = 0


class SecureBytes:
    """
    Contêiner simples para bytes sensíveis.

    - Armazena o conteúdo em um `bytearray` interno.
    - `to_bytes()` devolve uma CÓPIA (bytes) — após `clear()`, levanta `ValueError`.
    - `clear()` zera o buffer em memória e invalida leituras futuras.
    - `cleared` indica se o conteúdo já foi limpo.

    Observações:
    - Não faz mlock/VirtualLock: fora do escopo do projeto em Python puro.
    - Foco aqui é semântica correta + limpeza explícita e previsível.
    """

    __slots__ = ("_buf", "_closed")

    def __init__(self, data: BytesLike):
        if isinstance(data, memoryview):
            data = data.tobytes()
        elif isinstance(data, bytearray):
            # Fazemos uma cópia para evitar aliasing com referências externas.
            data = bytes(data)
        elif not isinstance(data, bytes):
            raise TypeError("SecureBytes espera bytes/bytearray/memoryview")
        self._buf = bytearray(data)
        self._closed = False

    def to_bytes(self) -> bytes:
        """
        Retorna uma cópia dos bytes originais.

        Após `clear()`, levanta `ValueError` para evitar uso acidental de
        dados que já deveriam estar fora de memória.
        """
        if self._closed:
            raise ValueError("SecureBytes already cleared")
        return bytes(self._buf)

    def clear(self) -> None:
        """
        Zeroiza o buffer interno e invalida leituras futuras.
        Idempotente: múltiplas chamadas não causam erro.
        """
        if not self._closed:
            _secure_memzero(self._buf)
            self._buf.clear()
            self._closed = True

    @property
    def cleared(self) -> bool:
        """Compat: indica se os bytes já foram limpos/descartados."""
        return self._closed

    def __len__(self) -> int:
        return 0 if self._closed else len(self._buf)

    def __repr__(self) -> str:
        state = "cleared" if self._closed else f"{len(self)} bytes"
        return f"<SecureBytes {state}>"
