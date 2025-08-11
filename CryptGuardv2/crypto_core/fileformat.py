from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Tuple

# ───────────────────────── constantes ───────────────────────────────────────
MAGIC = b"CG2\0"
VERSION = 4  # v4 remove 'orig_ext' do header (v3 tinha)
# Limit safeguard to avoid reading huge headers
MAX_HEADER_LEN = 1 << 20  # 1 MiB

# 1=AES-GCM, 2=XChaCha20-Poly1305, 3=ChaCha20-Poly1305, 4=AES-CTR(+HMAC)
AlgCode = Literal[1, 2, 3, 4]
ALG_MAP = {
    "AES-256-GCM": 1,
    "XChaCha20-Poly1305": 2,
    "ChaCha20-Poly1305": 3,
    "AES-256-CTR": 4,
}
REV_ALG_MAP = {v: k for k, v in ALG_MAP.items()}


# ───────────────────────── header ───────────────────────────────────────────
@dataclass
class CG2Header:
    """
    Cabeçalho CG2 v4 (sem 'orig_ext'):
      MAGIC | VERSION | ALG | KDF_LEN | KDF_JSON | NONCE_LEN | NONCE | EXP_TS
    Todos os campos do header são usados como AAD.
    """
    version: int
    alg: str
    kdf: dict            # {"name":"argon2id","salt":hex,"time_cost":..,"memory_cost":..,"parallelism":..}
    nonce: bytes
    exp_ts: int | None   # epoch seconds (None = sem expiração)

    def pack(self) -> bytes:
        # Validate algorithm
        try:
            alg_code = ALG_MAP[self.alg]
        except KeyError as e:
            raise ValueError(f"Unknown algorithm '{self.alg}'") from e

        # Validate nonce
        if not isinstance(self.nonce, (bytes, bytearray)):
            raise TypeError("nonce must be bytes")
        nonce_bytes = bytes(self.nonce)
        if len(nonce_bytes) > 0xFFFF:
            raise ValueError("nonce too long (must fit in 2 bytes length)")

        # Validate exp_ts
        exp = 0 if self.exp_ts is None else int(self.exp_ts)
        if exp < 0:
            raise ValueError("exp_ts must be >= 0")
        if exp >= (1 << 64):
            raise ValueError("exp_ts too large (must fit in uint64)")

        # Serialize KDF JSON
        try:
            kdf_blob = json.dumps(self.kdf, separators=(",", ":"), sort_keys=False).encode()
        except Exception as e:
            raise ValueError(f"Invalid KDF parameters: {e}") from e

        return b"".join([
            MAGIC,
            struct.pack(">B", VERSION if self.version != VERSION else self.version),
            struct.pack(">B", alg_code),
            struct.pack(">I", len(kdf_blob)), kdf_blob,
            struct.pack(">H", len(nonce_bytes)), nonce_bytes,
            struct.pack(">Q", exp),
            # v3 tinha: 1B len + bytes da extensão. v4 não grava mais nada aqui.
        ])

    @staticmethod
    def unpack(buf: bytes) -> Tuple["CG2Header", int, str]:
        """
        Desempacota o header a partir de 'buf' (que DEVE começar em MAGIC) e retorna:
          (header, offset_payload, orig_ext_legacy)

        Levanta ValueError("Truncated header (...)") quando não há bytes suficientes.
        """
        def need(n: int, what: str) -> None:
            if len(buf) < n:
                raise ValueError(f"Truncated header ({what})")

        if not buf.startswith(MAGIC):
            raise ValueError("Not a CG2 file (bad magic).")

        off = len(MAGIC)

        # versão
        need(off + 1, "version")
        ver = struct.unpack_from(">B", buf, off)[0]; off += 1
        if ver not in (3, 4):
            raise ValueError(f"Unsupported CG2 version {ver}")

        # algoritmo
        need(off + 1, "algorithm")
        alg_code = struct.unpack_from(">B", buf, off)[0]; off += 1
        alg = REV_ALG_MAP.get(alg_code)
        if not alg:
            raise ValueError("Unknown algorithm code")

        # kdf json
        need(off + 4, "kdf length")
        kdf_len = struct.unpack_from(">I", buf, off)[0]; off += 4
        need(off + kdf_len, "kdf json")
        kdf_blob = buf[off:off + kdf_len]; off += kdf_len
        try:
            kdf = json.loads(kdf_blob)
        except Exception as e:
            raise ValueError(f"Invalid KDF JSON: {e}") from e

        # nonce
        need(off + 2, "nonce length")
        nonce_len = struct.unpack_from(">H", buf, off)[0]; off += 2
        need(off + nonce_len, "nonce")
        nonce = buf[off:off + nonce_len]; off += nonce_len

        # expiração
        need(off + 8, "expiration")
        exp_ts = struct.unpack_from(">Q", buf, off)[0]; off += 8
        exp_ts = None if exp_ts == 0 else int(exp_ts)

        # extensão legada (v3)
        orig_ext = ""
        if ver == 3:
            need(off + 1, "legacy ext length")
            ext_len = struct.unpack_from(">B", buf, off)[0]; off += 1
            need(off + ext_len, "legacy ext")
            orig_ext = buf[off:off + ext_len].decode("utf-8", "ignore"); off += ext_len

        header = CG2Header(
            version=ver,
            alg=alg,
            kdf=kdf,
            nonce=nonce,
            exp_ts=exp_ts,
        )
        return header, off, orig_ext


# ───────────────────────── utilitários ──────────────────────────────────────
def is_cg2_file(path: str | Path) -> bool:
    """Retorna True se o arquivo começa com MAGIC."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == MAGIC
    except Exception:
        return False


def read_header(path: str | Path) -> Tuple[CG2Header, bytes, int, str]:
    """
    Lê o header de um arquivo .cg2 e retorna:
      (header, header_bytes_brutos, offset_payload, ext_legacy)

    Faz leitura incremental até ter bytes suficientes para o cabeçalho.
    """
    p = Path(path)
    with p.open("rb") as f:
        head = f.read(4)
        if head != MAGIC:
            raise ValueError("Not a CG2 file.")
        buf = head + f.read(4096)
        while True:
            try:
                header, off, ext_legacy = CG2Header.unpack(buf)
                raw = buf[:off]
                return header, raw, off, ext_legacy
            except ValueError as e:
                if "Truncated header" in str(e):
                    more = f.read(4096)
                    if not more:
                        raise
                    buf += more
                    if len(buf) > MAX_HEADER_LEN:
                        raise ValueError("Header too large")
                    continue
                raise

__all__ = [
    "MAGIC",
    "VERSION",
    "ALG_MAP",
    "REV_ALG_MAP",
    "CG2Header",
    "is_cg2_file",
    "read_header",
]
