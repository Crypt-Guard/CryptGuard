"""crypto_base.py – abstrações base para back‑ends de criptografia do CryptGuard v2

Este módulo concentra toda a lógica que antes estava duplicada nos arquivos
file_crypto*.py (AES‑GCM/CTR, ChaCha20‑Poly1305, XChaCha20‑Poly1305, streaming
ou single‑shot).

Classes principais
──────────────────
BaseCipher (ABC)
    • Classe abstrata com a API comum de criptografia/decifra.
    • Define helpers para derivar chaves, montar cabeçalhos + HMAC, lidar com
      rate‑limiting, expiração, metadados e encode/decode baseados em chunks.

StreamingMixin / SingleShotMixin
    • Encapsulam o fluxo de leitura/escrita em chunks (8 MiB) ou sub‑chunks
      (1 MiB) para manter compatibilidade com variantes *stream* e “shot”.
    • Proporcionam callbacks de progresso e uso do ThreadPoolExecutor.

Para criar um novo backend basta:

```python
class AesGcmCipher(StreamingMixin, BaseCipher):
    alg_tag       = b"AESG"
    hkdf_info     = b"PFA-keys"
    nonce_size    = 12
    use_global_hmac = True
    supports_rs   = True

    def encode_chunk(...):
        ...
    def decode_chunk(...):
        ...
```

Isso elimina ~70 % de código repetido.
"""
from __future__ import annotations

import os, struct, secrets, time, hmac, hashlib, queue, concurrent.futures
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, Optional, Tuple, Type
from io import BytesIO

from .config          import (
    MAGIC, ENC_EXT, META_EXT, CHUNK_SIZE, SINGLE_SHOT_SUBCHUNK_SIZE,
    USE_RS, RS_PARITY_BYTES, SIGN_METADATA, MAX_CLOCK_SKEW_SEC,
    SecurityProfile,
)
from .logger          import logger
from .rate_limit      import check_allowed, reset
from .hkdf_utils      import derive_keys as _hkdf
from .kdf             import derive_key
from .key_obfuscator  import TimedExposure
from .metadata        import encrypt_meta_json, decrypt_meta_json
from .utils           import (
    write_atomic_secure, pack_enc_zip, unpack_enc_zip,
    generate_unique_filename, check_expiry,
)

from .secure_bytes    import SecureBytes

# Tamanho fixo do cabeçalho (salt 16 B + MAGIC 4 B + alg_tag 4 B)
HEADER_LEN = 16 + 4 + 4

# ───────────────────────── classe base ────────────────────────────────────────
class BaseCipher(ABC):
    """Classe abstrata para back‑ends de criptografia."""

    # subclasses devem sobrescrever ↓↓↓
    alg_tag: bytes                # 4 B gravados após MAGIC
    hkdf_info: bytes              # "info" passado ao HKDF
    nonce_size: int               # 12 (ChaCha/AES‑GCM) ou 24 (XChaCha)
    use_global_hmac: bool = True  # grava/verifica HMAC? (AES‑CTR & afins)
    supports_rs: bool = True      # Reed‑Solomon opcional

    # ---------------------------------------------------------------------
    @classmethod
    def derive_keys(cls, pwd: str | SecureBytes, salt: bytes,
                    profile: SecurityProfile) -> Tuple[bytes, bytes]:
        """Argon2id → HKDF → (enc_key, hmac_key)."""
        pwd_sb = pwd if isinstance(pwd, SecureBytes) else SecureBytes(pwd.encode())
        master_obf = derive_key(pwd_sb, salt, profile)
        with TimedExposure(master_obf) as master:
            enc_key, hmac_key = _hkdf(master, info=cls.hkdf_info, salt=salt)
        master_obf.clear(); pwd_sb.clear()
        return enc_key, hmac_key

    # ------------------------------------------------------------------
    @classmethod
    def build_header(cls, salt: bytes, nonce: bytes = b"") -> bytes:
        """salt + MAGIC + alg_tag [+ nonce opcional]."""
        return salt + MAGIC + cls.alg_tag + nonce

    # ------------------------------------------------------------------
    # Métodos que cada backend deve implementar
    @staticmethod
    @abstractmethod
    def encode_chunk(idx: int, plain: bytes, nonce: bytes, enc_key: bytes,
                     rs_use: bool, header: bytes) -> Tuple[int, bytes]:
        """Encripta um chunk e devolve (idx, payload ordenável)."""

    @staticmethod
    @abstractmethod
    def decode_chunk(idx: int, cipher_blob: bytes, nonce: bytes,
                     enc_key: bytes, rs_use: bool, header: bytes) -> Tuple[int, bytes]:
        """Decifra chunk (idx, plain)."""

    # ------------------------------------------------------------------
    # API pública genérica
    # ------------------------------------------------------------------
    @classmethod
    def encrypt_file(cls: Type["BaseCipher"], src_path: os.PathLike | str,
                     password: str, *, profile: SecurityProfile,
                     progress_cb: Optional[Callable[[int], None]] = None,
                     expires_at: int | None = None, streaming: bool = False,
                     chunk_size: int = CHUNK_SIZE) -> str:
        """Implementação compartilhada de criptografia."""
        if not isinstance(src_path, Path):
            src_path = Path(src_path)
        size = src_path.stat().st_size
        salt = secrets.token_bytes(16)
        enc_key, hmac_key = cls.derive_keys(password, salt, profile)

        rs_use = USE_RS and RS_PARITY_BYTES > 0 and cls.supports_rs

        # Decide mixin
        mixin: "_FlowMixin" = StreamingMixin if streaming else SingleShotMixin
        encoder = mixin(cls)
        body = encoder.encrypt_flow(src_path, size, salt, enc_key, hmac_key,
                                    rs_use, progress_cb, chunk_size)

        # Cabeçalho
        header = cls.build_header(salt)
        out = header + body

        enc_path = src_path.with_suffix(src_path.suffix + ENC_EXT)
        if cls.use_global_hmac:
            hmac_bytes = hmac.new(hmac_key, out, hashlib.sha256).digest()
            write_atomic_secure(enc_path, out + hmac_bytes)
        else:
            write_atomic_secure(enc_path, out)

        hmac_hex = None
        if cls.use_global_hmac and SIGN_METADATA:
            hmac_hex = hmac.new(hmac_key, out, hashlib.sha256).hexdigest()

        meta = dict(alg=cls.alg_tag.decode(), profile=profile.name,
                    size=size, hmac=hmac_hex, use_rs=rs_use,
                    rs_bytes=RS_PARITY_BYTES if rs_use else 0,
                    ts=int(time.time()))
        if streaming:
            meta["chunk"] = True
        encrypt_meta_json(enc_path.with_suffix(enc_path.suffix + META_EXT),
                          meta, SecureBytes(password.encode()), expires_at)

        logger.info("%s enc %s (%.1f MiB)", cls.__name__, src_path.name,
                    size / 1_048_576)
        return str(pack_enc_zip(enc_path))

    @classmethod
    def decrypt_file(cls: Type["BaseCipher"], enc_path: os.PathLike | str,
                     password: str, *, profile_hint: SecurityProfile,
                     progress_cb: Optional[Callable[[int], None]] = None,
                     chunk_size: int = CHUNK_SIZE, original_path: Path = None) -> str:
        """Descriptografa .enc ou .zip.
        Retorna path do arquivo restaurado."""
        if not check_allowed(str(enc_path)):
            raise RuntimeError("Muitas tentativas falhas; aguarde.")

        if str(enc_path).lower().endswith(".zip"):
            src, _tmp = unpack_enc_zip(Path(enc_path))
        else:
            src, _tmp = Path(enc_path), None

        file_bytes = src.read_bytes()
        blob = file_bytes
        enc_key = hmac_key = None
        if cls.use_global_hmac:
            if len(file_bytes) < 32:
                raise ValueError("File too small for HMAC")
            blob, file_hmac = file_bytes[:-32], file_bytes[-32:]
        with BytesIO(blob) as fin:
            salt = fin.read(16)
            magic, tag = fin.read(4), fin.read(4)
            if magic != MAGIC or tag != cls.alg_tag:
                raise ValueError("Formato desconhecido.")

        enc_key, hmac_key = cls.derive_keys(password, salt, profile_hint)
        if cls.use_global_hmac:
            calc = hmac.new(hmac_key, blob, hashlib.sha256).digest()
            if not hmac.compare_digest(calc, file_hmac):
                raise ValueError("Appended HMAC invalid – file tampered or wrong password")

        meta = decrypt_meta_json(src.with_suffix(src.suffix + META_EXT),
                                 SecureBytes(password.encode()))
        check_expiry(meta, MAX_CLOCK_SKEW_SEC)
        rs_use = meta.get("use_rs", False)
        size   = meta["size"]

        if cls.alg_tag == b"ACTR" and not meta.get("hmac"):
            raise ValueError("Arquivo AES‑CTR sem HMAC – rejeitado (integridade ausente)")

        if cls.use_global_hmac and meta.get("hmac"):
            calc_hex = hmac.new(hmac_key, blob, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(calc_hex, meta.get("hmac", "")):
                raise ValueError("Metadata HMAC mismatch – possible tampering")

        mixin: "_FlowMixin" = StreamingMixin if meta.get("chunk") else SingleShotMixin
        decoder = mixin(cls)
        plain_data = decoder.decrypt_flow(blob, size, salt, enc_key, rs_use,
                                          progress_cb, chunk_size)

        if len(plain_data) != size:
            raise ValueError("Decrypted size does not match expected - file may be corrupted, tampered, or decrypted with wrong algorithm.")

        out_dir = Path(original_path).parent if original_path else src.parent
        out_name = src.with_suffix("").name
        out_path = generate_unique_filename(out_dir / out_name)
        write_atomic_secure(out_path, plain_data)
        logger.info("%s dec %s -> %s", cls.__name__, src.name, out_path.name)
        reset(str(enc_path))
        return str(out_path)

# ───────────────────────── mixins de fluxo ──────────────────────────────────
class _FlowMixin(ABC):
    """Interface para mixins de fluxo (streaming vs single‑shot)."""
    def __init__(self, cipher_cls: Type[BaseCipher]):
        self.cipher_cls = cipher_cls

    @abstractmethod
    def encrypt_flow(self, src: Path, size: int, salt: bytes,
                     enc_key: bytes, hmac_key: bytes, rs_use: bool,
                     cb: Optional[Callable[[int], None]], chunk_size: int) -> bytes: ...

    @abstractmethod
    def decrypt_flow(self, blob: bytes, size: int, salt: bytes,
                     enc_key: bytes, rs_use: bool,
                     cb: Optional[Callable[[int], None]], chunk_size: int) -> bytes: ...

class StreamingMixin(_FlowMixin):
    """Processa arquivo em chunks (padrão 8 MiB) usando ThreadPoolExecutor."""

    def encrypt_flow(self, src: Path, size: int, salt: bytes, enc_key: bytes,
                     hmac_key: bytes, rs_use: bool, cb: Optional[Callable],
                     chunk_size: int) -> bytes:
        pq: "queue.PriorityQueue[Tuple[int, bytes]]" = queue.PriorityQueue()
        futures = []
        processed = 0
        header = salt + MAGIC + self.cipher_cls.alg_tag
        plain_sizes: list[int] = []
        with src.open("rb", buffering=chunk_size*4) as fin, \
             concurrent.futures.ThreadPoolExecutor() as ex:
            idx = 0
            while (chunk := fin.read(chunk_size)):
                nonce = secrets.token_bytes(self.cipher_cls.nonce_size)
                fut = ex.submit(self.cipher_cls.encode_chunk, idx, chunk, nonce,
                                 enc_key, rs_use, header)
                futures.append(fut)
                plain_sizes.append(len(chunk))
                idx += 1
            total_chunks = idx
            errors = []
            for fut in concurrent.futures.as_completed(futures):
                exc = fut.exception()
                if exc:
                    errors.append(exc)
                    for f in futures: f.cancel()
                    break
                idx2, payload = fut.result()
                pq.put((idx2, payload))
                processed += plain_sizes[idx2]
                if cb: cb(min(processed, size))
            if errors:
                raise errors[0]
            if pq.qsize() != total_chunks:
                raise RuntimeError("Inconsistência de chunks.")
        body = bytearray()
        while not pq.empty():
            _, payload = pq.get()
            body += payload
        return bytes(body)

    def decrypt_flow(self, blob: bytes, size: int, salt: bytes, enc_key: bytes,
                     rs_use: bool, cb: Optional[Callable], chunk_size: int) -> bytes:
        pq: "queue.PriorityQueue[Tuple[int, bytes]]" = queue.PriorityQueue()
        futures = []
        processed = 0
        header = salt + MAGIC + self.cipher_cls.alg_tag
        with BytesIO(blob) as fin, concurrent.futures.ThreadPoolExecutor() as ex:
            fin.seek(HEADER_LEN)
            idx = 0
            expected_hdr = self.cipher_cls.nonce_size + 4
            while (hdr := fin.read(expected_hdr)):
                if len(hdr) != expected_hdr:
                    raise ValueError("Truncated chunk header")
                nonce = hdr[:self.cipher_cls.nonce_size]
                (clen,) = struct.unpack(">I", hdr[self.cipher_cls.nonce_size:])
                cipher_blob = fin.read(clen)
                if len(cipher_blob) != clen:
                    raise ValueError("Truncated chunk payload")
                fut = ex.submit(self.cipher_cls.decode_chunk, idx, cipher_blob,
                                 nonce, enc_key, rs_use, header)
                futures.append(fut); idx += 1
            total_chunks = idx
            errors = []
            for fut in concurrent.futures.as_completed(futures):
                exc = fut.exception()
                if exc:
                    errors.append(exc)
                    for f in futures: f.cancel()
                    break
                idx2, plain = fut.result()
                pq.put((idx2, plain))
                processed += len(plain)
                if cb: cb(min(processed, size))
            if errors:
                raise errors[0]
            if pq.qsize() != total_chunks:
                raise RuntimeError("Inconsistência de chunks.")
        body = bytearray()
        while not pq.empty():
            _, plain = pq.get()
            body += plain
        return bytes(body)

class SingleShotMixin(_FlowMixin):
    """Processa arquivo completo em sub‑chunks (1 MiB) em memória."""

    def encrypt_flow(self, src: Path, size: int, salt: bytes, enc_key: bytes,
                     hmac_key: bytes, rs_use: bool, cb: Optional[Callable],
                     chunk_size: int) -> bytes:
        data = src.read_bytes()
        n_sub = max(1, (len(data) + SINGLE_SHOT_SUBCHUNK_SIZE - 1)//SINGLE_SHOT_SUBCHUNK_SIZE)
        body = bytearray()
        header = salt + MAGIC + self.cipher_cls.alg_tag
        processed = 0
        for idx in range(n_sub):
            sub = data[idx*SINGLE_SHOT_SUBCHUNK_SIZE:(idx+1)*SINGLE_SHOT_SUBCHUNK_SIZE]
            nonce = secrets.token_bytes(self.cipher_cls.nonce_size)
            _, payload = self.cipher_cls.encode_chunk(idx, sub, nonce, enc_key, rs_use, header)
            body += payload
            processed += len(sub)
            if cb: cb(min(processed, size))
        return bytes(body)

    def decrypt_flow(self, blob: bytes, size: int, salt: bytes, enc_key: bytes,
                     rs_use: bool, cb: Optional[Callable], chunk_size: int) -> bytes:
        pos = HEADER_LEN
        out = bytearray()
        idx = 0
        header = blob[:HEADER_LEN]
        while pos < len(blob):
            expected_hdr = self.cipher_cls.nonce_size + 4
            if pos + expected_hdr > len(blob):
                raise ValueError("Truncated chunk header")
            nonce = blob[pos:pos+self.cipher_cls.nonce_size]
            pos += self.cipher_cls.nonce_size
            (clen,) = struct.unpack(">I", blob[pos:pos+4]); pos += 4
            if pos + clen > len(blob):
                raise ValueError("Truncated chunk payload")
            cipher_blob = blob[pos:pos+clen]; pos += clen
            _, plain = self.cipher_cls.decode_chunk(idx, cipher_blob, nonce,
                                                     enc_key, rs_use, header)
            out += plain
            if cb: cb(min(len(out), size))
            idx += 1
        return bytes(out)
