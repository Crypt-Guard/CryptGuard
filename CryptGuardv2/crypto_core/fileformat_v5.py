from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

# CG2 v5 header (all bytes are AAD)
# MAGIC(4) | VERSION(1=0x05) | ALG_ID(1=0x01) | KDF_LEN(u16) | KDF_JSON | SS_HEADER(24)

MAGIC = b"CG25"
VERSION = 0x05
ALG_ID = 0x01  # fixed: XChaCha20-Poly1305 SecretStream

MAX_HEADER_LEN = 1 << 20  # 1 MiB safety cap
SS_HEADER_BYTES = 24


def canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


@dataclass
class V5Header:
    kdf_params_json: bytes
    ss_header: bytes

    def pack(self) -> bytes:
        if not isinstance(self.kdf_params_json, (bytes, bytearray)):
            raise TypeError("kdf_params_json must be bytes")
        kdf_blob = bytes(self.kdf_params_json)
        if len(kdf_blob) > 0xFFFF:
            raise ValueError("KDF params too large (must fit in u16)")
        if not isinstance(self.ss_header, (bytes, bytearray)) or len(self.ss_header) != SS_HEADER_BYTES:
            raise ValueError("ss_header must be 24 bytes")
        return b"".join(
            [
                MAGIC,
                struct.pack(">B", VERSION),
                struct.pack(">B", ALG_ID),
                struct.pack(">H", len(kdf_blob)),
                kdf_blob,
                bytes(self.ss_header),
            ]
        )


def parse_header(buf: bytes) -> Tuple[V5Header, int]:
    """
    Parse a v5 header from the given bytes buffer (must start at MAGIC).
    Returns (V5Header, offset_after_header).
    """
    def need(n: int, what: str) -> None:
        if len(buf) < n:
            raise ValueError(f"Truncated header ({what})")

    if not buf.startswith(MAGIC):
        raise ValueError("Not a CG2 v5 file (bad magic).")
    off = len(MAGIC)

    # version
    need(off + 1, "version")
    ver = struct.unpack_from(">B", buf, off)[0]
    off += 1
    if ver != VERSION:
        raise ValueError(f"Unsupported CG2 version {ver}")

    # algorithm id
    need(off + 1, "alg id")
    alg_id = struct.unpack_from(">B", buf, off)[0]
    off += 1
    if alg_id != ALG_ID:
        raise ValueError("Unsupported algorithm id for v5")

    # kdf json
    need(off + 2, "kdf length")
    kdf_len = struct.unpack_from(">H", buf, off)[0]
    off += 2
    need(off + kdf_len, "kdf json")
    kdf_blob = buf[off : off + kdf_len]
    off += kdf_len

    # ss header
    need(off + SS_HEADER_BYTES, "secretstream header")
    ss_header = buf[off : off + SS_HEADER_BYTES]
    off += SS_HEADER_BYTES

    return V5Header(kdf_params_json=kdf_blob, ss_header=ss_header), off


def read_v5_header(path: str | Path) -> tuple[V5Header, bytes, int]:
    p = Path(path)
    with p.open("rb") as f:
        head = f.read(4)
        if head != MAGIC:
            raise ValueError("Not a CG2 v5 file.")
        buf = head + f.read(4096)
        while True:
            try:
                hdr, off = parse_header(buf)
                raw = buf[:off]
                return hdr, raw, off
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


def read_header_version_any(path: str | Path) -> int:
    p = Path(path)
    with p.open("rb") as f:
        magic = f.read(4)
    if magic == MAGIC:
        return VERSION
    # legacy magic handled by legacy reader
    from .fileformat import MAGIC as LEG_MAGIC, read_header as legacy_read
    if magic == LEG_MAGIC:
        try:
            hdr, _, _, _ = legacy_read(path)
            return int(hdr.version)
        except Exception as e:
            raise ValueError(f"Failed to read legacy header: {e}") from e
    raise ValueError("Unknown file format (magic)")


__all__ = [
    "MAGIC",
    "VERSION",
    "ALG_ID",
    "SS_HEADER_BYTES",
    "V5Header",
    "parse_header",
    "read_v5_header",
    "read_header_version_any",
    "canonical_json_bytes",
]

