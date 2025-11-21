from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path

from .versioning import MIN_SUPPORTED_VERSION, UnsupportedFormatVersionError

# CG2 v5 header (all bytes are AAD)
# MAGIC(4) | VERSION(1=0x05) | ALG_ID(1=0x01) | KDF_LEN(u16, BE) | KDF_JSON | SS_HEADER(24)

MAGIC = b"CG25"
VERSION = 0x05
ALG_ID = 0x01  # fixed: XChaCha20-Poly1305 SecretStream

SS_HEADER_BYTES = 24
MAX_HEADER_LEN = 1 << 20  # 1 MiB safety cap


def canonical_json_bytes(obj: object) -> bytes:
    """
    Serialize JSON in a deterministic (canonical) way:
    - UTF-8 bytes
    - sort_keys=True
    - no spaces (separators=(",", ":"))
    - forbid NaN/Infinity
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class V5Header:
    kdf_params_json: bytes
    ss_header: bytes

    @property
    def version(self) -> int:
        return VERSION

    @property
    def alg_id(self) -> int:
        return ALG_ID

    def pack(self) -> bytes:
        if not isinstance(self.kdf_params_json, bytes | bytearray):
            raise TypeError("kdf_params_json must be bytes")
        if len(self.ss_header) != SS_HEADER_BYTES:
            raise ValueError("Bad SecretStream header size")
        klen = len(self.kdf_params_json)
        if klen == 0 or klen > 0xFFFF:
            raise ValueError("Invalid KDF length")
        return b"".join(
            [
                MAGIC,
                struct.pack(">B", VERSION),
                struct.pack(">B", ALG_ID),
                struct.pack(">H", klen),
                bytes(self.kdf_params_json),
                self.ss_header,
            ]
        )


def parse_header(buf: bytes) -> tuple[V5Header, int]:
    """
    Parse a v5 header from the given bytes buffer (must start at MAGIC).
    Returns (V5Header, offset_after_header).
    """
    if len(buf) < len(MAGIC):
        raise ValueError("Truncated header (magic)")

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
    if ver < MIN_SUPPORTED_VERSION:
        raise UnsupportedFormatVersionError(
            f"Arquivo em formato muito antigo (v{ver}); min_supported={MIN_SUPPORTED_VERSION}. Atualize o arquivo/ferramenta."
        )
    if ver != VERSION:
        raise ValueError(f"Unsupported CG2 v5 version byte: {ver}")

    # alg id
    need(off + 1, "alg id")
    alg = struct.unpack_from(">B", buf, off)[0]
    off += 1
    if alg != ALG_ID:
        raise ValueError(f"Unsupported ALG_ID: {alg}")

    # kdf len
    need(off + 2, "kdf_len")
    (kdf_len,) = struct.unpack_from(">H", buf, off)
    off += 2
    if kdf_len == 0 or kdf_len > 0xFFFF:
        raise ValueError("Invalid KDF length")
    need(off + kdf_len, "kdf_json")
    kdf_json = bytes(buf[off : off + kdf_len])
    off += kdf_len

    # secretstream header
    need(off + SS_HEADER_BYTES, "ss_header")
    ss_header = bytes(buf[off : off + SS_HEADER_BYTES])
    off += SS_HEADER_BYTES

    hdr = V5Header(kdf_params_json=kdf_json, ss_header=ss_header)
    return hdr, off


def _read_v5_header_stream(fp) -> tuple[V5Header, bytes, int]:
    def _read(src, n: int) -> bytes:
        b = src.read(n)
        if b is None or len(b) < n:
            raise ValueError("Truncated header")
        return b

    prefix = _read(fp, 8)  # MAGIC + VER + ALG + KDF_LEN
    if not prefix.startswith(MAGIC):
        raise ValueError("Not a CG2 v5 file (bad magic)")
    ver = prefix[4]
    alg = prefix[5]
    if ver < MIN_SUPPORTED_VERSION:
        raise UnsupportedFormatVersionError(
            f"Arquivo em formato muito antigo (v{ver}); min_supported={MIN_SUPPORTED_VERSION}. Atualize o arquivo/ferramenta."
        )
    if ver != VERSION:
        raise ValueError(f"Unsupported CG2 v5 version byte: {ver}")
    if alg != ALG_ID:
        raise ValueError(f"Unsupported ALG_ID: {alg}")
    kdf_len = struct.unpack_from(">H", prefix, 6)[0]
    if kdf_len == 0 or kdf_len > 0xFFFF:
        raise ValueError("Invalid KDF length")
    rest_len = kdf_len + SS_HEADER_BYTES
    if 8 + rest_len > MAX_HEADER_LEN:
        raise ValueError("Header too large")
    rest = _read(fp, rest_len)
    header_bytes = prefix + rest
    hdr, off = parse_header(header_bytes)
    return hdr, header_bytes, off


def read_v5_header(path_or_file) -> tuple[V5Header, bytes, int]:
    """
    Reads the v5 header from a file path or file-like object opened in binary mode.
    Returns (V5Header, header_bytes, offset_after_header).
    """
    if hasattr(path_or_file, "read"):
        return _read_v5_header_stream(path_or_file)
    with open(Path(path_or_file), "rb") as fp:
        return _read_v5_header_stream(fp)


def _read_header_version_stream(fp) -> int:
    magic = fp.read(4)
    if len(magic) < 4:
        raise ValueError("Truncated header")
    if magic == MAGIC:
        ver_b = fp.read(1)
        if len(ver_b) != 1:
            raise ValueError("Truncated header")
        ver = ver_b[0]
        if ver < MIN_SUPPORTED_VERSION:
            raise UnsupportedFormatVersionError(
                f"Arquivo em formato muito antigo (v{ver}); min_supported={MIN_SUPPORTED_VERSION}. Atualize o arquivo/ferramenta."
            )
        return ver
    if magic == b"CG2\0":
        ver_b = fp.read(1)  # legacy v1–v4
        if len(ver_b) != 1:
            raise ValueError("Truncated legacy header")
        ver = ver_b[0]
        if ver < MIN_SUPPORTED_VERSION:
            raise UnsupportedFormatVersionError(
                f"Arquivo em formato muito antigo (v{ver}); min_supported={MIN_SUPPORTED_VERSION}. Atualize o arquivo/ferramenta."
            )
        return ver
    raise ValueError("Unknown file format (magic)")


def read_header_version_any(path_or_file) -> int:
    """
    Detect header version for CG2 files.
    Returns an int (e.g., 5 for v5). Raises if neither legacy nor v5.
    """
    if hasattr(path_or_file, "read"):
        return _read_header_version_stream(path_or_file)
    with open(Path(path_or_file), "rb") as fp:
        return _read_header_version_stream(fp)


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
