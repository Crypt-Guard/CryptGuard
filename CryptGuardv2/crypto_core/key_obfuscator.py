# crypto_core/key_obfuscator.py
from __future__ import annotations

import contextlib
import ctypes
import secrets
from typing import Optional

from .secure_bytes import SecureBytes


def _secure_memzero(buf: bytearray) -> None:
    """Idêntico ao de secure_bytes: tenta Windows API, senão memset, senão loop."""
    if not buf:
        return
    n = len(buf)
    try:
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
        try:
            _rtl = ctypes.windll.kernel32.RtlSecureZeroMemory  # type: ignore[attr-defined]
            _rtl.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
            _rtl.restype = ctypes.c_void_p
            _rtl(addr, n)
            return
        except Exception:
            pass  # nosec B110 (fallback intencional; caminho alternativo abaixo)
        ctypes.memset(addr, 0, n)
    except Exception:
        for i in range(n):
            buf[i] = 0


class KeyObfuscator:
    """
    Obfuscador leve para reduzir o tempo de chave em claro na RAM.

    Modelo: XOR com máscara aleatória (one-time mask):
      - `masked = plain ^ mask`
      - Para recuperar: `plain = masked ^ mask`
      - `obfuscate()` remasca SEM materializar plaintext:
            masked' = masked ^ mask ^ new_mask
            mask    = new_mask

    Uso típico:
        sb = SecureBytes(key_bytes)
        obf = KeyObfuscator(sb)         # sb é zerado internamente
        with obf.expose() as exp:       # exp é SecureBytes em claro, limpo ao sair
            use(exp.to_bytes())

        # ou:
        k = obf.deobfuscate()           # SecureBytes (lembre-se de k.clear() depois)

    Segurança/coerência:
      - Rejeita chave vazia.
      - `clear()` zera e invalida definitivamente.
      - `expose()` é NÃO-REENTRANTE por padrão (bloqueia exposições simultâneas).
    """

    __slots__ = ("_masked", "_mask", "_cleared", "_exposed")

    def __init__(self, key_sb: SecureBytes):
        plain = key_sb.to_bytes()  # ValueError se já estiver limpo
        if not plain:
            key_sb.clear()
            raise ValueError("Empty key is not allowed")

        # Gera máscara e aplica XOR sem criar cópias redundantes
        self._mask = bytearray(secrets.token_bytes(len(plain)))
        self._masked = bytearray(a ^ b for a, b in zip(plain, self._mask, strict=False))
        self._cleared = False
        self._exposed = False  # controle simples de não-reentrância

        # Zera o SecureBytes de origem o quanto antes
        key_sb.clear()
        del plain

    # -------------------- propriedades/estado
    @property
    def cleared(self) -> bool:
        return self._cleared or (not self._mask) or (not self._masked)

    # -------------------- operações principais
    def deobfuscate(self) -> SecureBytes:
        """
        Reconstrói o plaintext (em um novo SecureBytes).
        Lança se já tiver sido `clear()` ou se o estado estiver inválido.
        """
        if self.cleared:
            raise RuntimeError("Key material has been cleared or is invalid")
        # XOR sem criar listas intermediárias grandes
        n = len(self._masked)
        out = bytearray(n)
        mv_m = memoryview(self._masked)
        mv_k = memoryview(self._mask)
        for i in range(n):
            out[i] = mv_m[i] ^ mv_k[i]
        return SecureBytes(out)

    def obfuscate(self) -> None:
        """
        Remasca SEM materializar o plaintext.
        Útil para reduzir ainda mais a janela de exposição ao longo do tempo.
        """
        if self.cleared:
            return
        n = len(self._mask)
        new_mask = bytearray(secrets.token_bytes(n))
        # masked' = masked ^ mask ^ new_mask
        mv_masked = memoryview(self._masked)
        mv_old = memoryview(self._mask)
        for i in range(n):
            mv_masked[i] = mv_masked[i] ^ mv_old[i] ^ new_mask[i]
        _secure_memzero(self._mask)
        self._mask = new_mask

    def clear(self) -> None:
        """Zera os buffers e invalida definitivamente (idempotente)."""
        if self._cleared:
            return
        _secure_memzero(self._masked)
        _secure_memzero(self._mask)
        self._masked.clear()
        self._mask.clear()
        self._cleared = True
        # Libera lock de exposição, se houver (defensivo)
        self._exposed = False

    # -------------------- exposição controlada
    def expose(self) -> "TimedExposure":
        """
        Context manager de exposição temporária:
            with obf.expose() as sb:
                # usa sb.to_bytes()
        Garante limpeza ao sair do `with`.
        """
        return TimedExposure(self)

    def __del__(self):
        with contextlib.suppress(Exception):
            self.clear()

    def __repr__(self) -> str:
        state = "cleared" if self.cleared else f"{len(self._masked)} bytes (obfuscated)"
        return f"<KeyObfuscator {state}>"


class TimedExposure(contextlib.AbstractContextManager):
    """
    Exposição temporária do plaintext (como SecureBytes), com limpeza garantida.
    Não-reentrante: bloqueia exposições simultâneas da MESMA instância de KeyObfuscator.
    """

    __slots__ = ("_obf", "_plain")

    def __init__(self, obf: KeyObfuscator):
        self._obf = obf
        self._plain: Optional[SecureBytes] = None

    def __enter__(self) -> SecureBytes:
        if self._plain is not None:
            raise RuntimeError("Re-entrant exposure is not allowed")
        if self._obf.cleared:
            raise RuntimeError("Cannot expose a cleared KeyObfuscator")
        if self._obf._exposed:
            # bloqueio de exposições simultâneas da MESMA instância
            raise RuntimeError("This KeyObfuscator is already exposed")
        self._obf._exposed = True
        self._plain = self._obf.deobfuscate()
        return self._plain

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        try:
            if self._plain is not None:
                self._plain.clear()
                self._plain = None
        finally:
            self._obf._exposed = False
