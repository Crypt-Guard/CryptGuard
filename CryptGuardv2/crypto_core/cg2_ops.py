"""
cg2_ops_v2.py - Versão refatorada com 100% de compatibilidade

CG2 operations – streaming com header autenticado (AAD), 4 algoritmos e proteção
contra truncamento + padding de tamanho + extensão original cifrada no rodapé.

Algoritmos:
  1) AES-256-GCM                 (nonce 12)
  2) XChaCha20-Poly1305          (nonce 24)  – via cryptography OU PyNaCl (fallback)
  3) ChaCha20-Poly1305 (IETF)    (nonce 12)
  4) AES-256-CTR + HMAC-SHA256   (IV 16)  → rodapé: [NAM0]* [SIZ0|8B] TAG0|32B

Refatorado em classes especializadas mantendo total compatibilidade.
"""

from __future__ import annotations

import hmac as py_hmac
import os
import struct
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)

# XChaCha – cryptography (se disponível)
try:
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
    XCH_CRYPTO_AVAILABLE = True
except Exception:
    XChaCha20Poly1305 = None  # type: ignore
    XCH_CRYPTO_AVAILABLE = False

# Fallback PyNaCl (libsodium) para XChaCha
try:
    from nacl.bindings import (
        crypto_aead_xchacha20poly1305_ietf_decrypt as nacl_xch_decrypt,
    )
    from nacl.bindings import (
        crypto_aead_xchacha20poly1305_ietf_encrypt as nacl_xch_encrypt,
    )
    NACL_XCH_AVAILABLE = True
except Exception:
    NACL_XCH_AVAILABLE = False

import contextlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import ARGON_PARAMS, CG2_EXT, CHUNK_SIZE, SecurityProfile
from .fileformat import CG2Header, read_header
from .kdf import derive_key
from .logger import logger

AEAD_SET = {"AES-256-GCM", "XChaCha20-Poly1305", "ChaCha20-Poly1305"}

# ───────────────────────── constants / footers ──────────────────────────────
END_MAGIC = b"END0"  # AEAD footer (final tag com chunks/total_pt)
TAG_MAGIC = b"TAG0"  # CTR HMAC tag
SIZ_MAGIC = b"SIZ0"  # CTR total_pt (opcional, antes do TAG0)
NAME_MAGIC = b"NAM0"  # bloco opcional com a extensão original cifrada

# ════════════════════════════════════════════════════════════════════════════
#                              DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class CG2Context:
    """Contexto compartilhado para operações CG2."""
    algorithm: str
    master_key: bytes
    enc_key: bytes
    mac_key: Optional[bytes]
    base_nonce: bytes
    header_aad: bytes
    salt: bytes
    profile: SecurityProfile
    pad_block_size: int = 0
    original_extension: str = ""
    expiration_ts: Optional[int] = None

@dataclass
class ChunkMetadata:
    """Metadados de um chunk processado."""
    index: int
    original_size: int
    padded_size: int
    nonce: bytes

# ════════════════════════════════════════════════════════════════════════════
#                            HELPER FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════

def _derive_chunk_nonce(base: bytes, idx: int) -> bytes:
    """Reusa o prefixo e xora contador de 32 bits no final (big-endian)."""
    ctr = int.from_bytes(base[-4:], "big") ^ idx
    return base[:-4] + ctr.to_bytes(4, "big")

def _split_enc_mac_keys(mk: bytes) -> tuple[bytes, bytes]:
    """Para AES-CTR (+HMAC): deriva (enc_key, mac_key) via HKDF-SHA256."""
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b"cg2-ctr-hkdf-v1").derive(mk)
    return okm[:32], okm[32:]

def _final_tag_key(mk: bytes) -> bytes:
    """Deriva chave para o footer AEAD (detecção de truncamento)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"cg2-final-tag-v1").derive(mk)

def _name_key(mk: bytes) -> bytes:
    """Chave para cifrar o bloco NAM0 (extensão original)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"cg2-name-v1").derive(mk)

def _pad(pt: bytes, block: int) -> bytes:
    """Padding com zeros até múltiplo de `block` (0 = sem padding)."""
    if block <= 0:
        return pt
    pad = (-len(pt)) % block
    if pad == 0:
        return pt
    return pt + (b"\x00" * pad)

def _guess_extension(first_bytes: bytes) -> str | None:
    """Detecção simples por magic bytes; retorna '.ext' ou None."""
    b = first_bytes
    b4 = b[:4] if len(b) >= 4 else b

    # imagens
    if b.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if b.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if b.startswith(b"GIF87a") or b.startswith(b"GIF89a"):
        return ".gif"
    if len(b) >= 12 and b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return ".webp"
    if b.startswith(b"BM"):
        return ".bmp"

    # docs/arquivos
    if b4 == b"%PDF":
        return ".pdf"
    if b4 in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return ".zip"  # docx/xlsx também são zip
    if b.startswith(b"7z\xbc\xaf\x27\x1c"):
        return ".7z"
    if b4 == b"Rar!":
        return ".rar"
    if b4 == b"\x1f\x8b\x08":
        return ".gz"
    if len(b) >= 265 and b[257:262] == b"ustar":
        return ".tar"

    # audio/vídeo
    if b4 == b"ID3" or (len(b) > 1 and b[0] == 0xFF and (b[1] & 0xE0) == 0xE0):
        return ".mp3"
    if len(b) >= 12 and b4 == b"\x00\x00\x00\x18" and b[4:8] == b"ftyp":
        return ".mp4"
    if b4 == b"OggS":
        return ".ogg"
    if b4 == b"fLaC":
        return ".flac"

    # texto
    if b:
        printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in b[:256])
        if printable / max(1, len(b[:256])) > 0.95:
            return ".txt"

    return None

# ════════════════════════════════════════════════════════════════════════════
#                           CHUNK PROCESSORS
# ════════════════════════════════════════════════════════════════════════════

class ChunkProcessor(ABC):
    """Base abstrata para processamento de chunks."""
    
    @abstractmethod
    def encrypt_chunk(self, chunk: bytes, index: int, ctx: CG2Context) -> bytes:
        """Encripta um chunk e retorna o payload framed."""
        pass
    
    @abstractmethod
    def decrypt_chunk(self, cipher_blob: bytes, nonce: bytes, index: int, ctx: CG2Context) -> bytes:
        """Decripta um chunk e retorna o plaintext."""
        pass

class AESGCMProcessor(ChunkProcessor):
    """Processador para AES-256-GCM."""
    
    def encrypt_chunk(self, chunk: bytes, index: int, ctx: CG2Context) -> bytes:
        if ctx.pad_block_size > 0:
            chunk = _pad(chunk, ctx.pad_block_size)
            
        nonce = _derive_chunk_nonce(ctx.base_nonce, index)
        if len(nonce) != 12:
            raise ValueError(f"Invalid nonce length: expected 12 bytes")
            
        ct = AESGCM(ctx.enc_key).encrypt(nonce, chunk, ctx.header_aad)
        return nonce + struct.pack(">I", len(ct)) + ct
    
    def decrypt_chunk(self, cipher_blob: bytes, nonce: bytes, index: int, ctx: CG2Context) -> bytes:
        if len(nonce) != 12:
            raise ValueError(f"Invalid nonce length: expected 12 bytes")
        return AESGCM(ctx.enc_key).decrypt(nonce, cipher_blob, ctx.header_aad)

class ChaCha20Processor(ChunkProcessor):
    """Processador para ChaCha20-Poly1305 (IETF)."""
    
    def encrypt_chunk(self, chunk: bytes, index: int, ctx: CG2Context) -> bytes:
        if ctx.pad_block_size > 0:
            chunk = _pad(chunk, ctx.pad_block_size)
            
        nonce = _derive_chunk_nonce(ctx.base_nonce, index)
        if len(nonce) != 12:
            raise ValueError(f"Invalid nonce length: expected 12 bytes")
            
        ct = ChaCha20Poly1305(ctx.enc_key).encrypt(nonce, chunk, ctx.header_aad)
        return nonce + struct.pack(">I", len(ct)) + ct
    
    def decrypt_chunk(self, cipher_blob: bytes, nonce: bytes, index: int, ctx: CG2Context) -> bytes:
        return ChaCha20Poly1305(ctx.enc_key).decrypt(nonce, cipher_blob, ctx.header_aad)

class XChaCha20Processor(ChunkProcessor):
    """Processador para XChaCha20-Poly1305 com fallbacks."""
    
    def encrypt_chunk(self, chunk: bytes, index: int, ctx: CG2Context) -> bytes:
        if ctx.pad_block_size > 0:
            chunk = _pad(chunk, ctx.pad_block_size)
            
        nonce = _derive_chunk_nonce(ctx.base_nonce, index)
        if len(nonce) != 24:
            raise ValueError(f"Invalid nonce length: expected 24 bytes")
        
        if XCH_CRYPTO_AVAILABLE and XChaCha20Poly1305:
            ct = XChaCha20Poly1305(ctx.enc_key).encrypt(nonce, chunk, ctx.header_aad)
        elif NACL_XCH_AVAILABLE:
            ct = nacl_xch_encrypt(chunk, ctx.header_aad, nonce, ctx.enc_key)
        else:
            try:
                from .compat_chacha import ChaCha20_Poly1305
                cipher = ChaCha20_Poly1305.new(key=ctx.enc_key, nonce=nonce)
                ct_core, tag = cipher.encrypt_and_digest(chunk, ctx.header_aad)
                ct = ct_core + tag
            except Exception:
                raise RuntimeError("Backend XChaCha20 indisponível.")
                
        return nonce + struct.pack(">I", len(ct)) + ct
    
    def decrypt_chunk(self, cipher_blob: bytes, nonce: bytes, index: int, ctx: CG2Context) -> bytes:
        if XCH_CRYPTO_AVAILABLE and XChaCha20Poly1305:
            return XChaCha20Poly1305(ctx.enc_key).decrypt(nonce, cipher_blob, ctx.header_aad)
        elif NACL_XCH_AVAILABLE:
            return nacl_xch_decrypt(cipher_blob, ctx.header_aad, nonce, ctx.enc_key)
        else:
            try:
                from .compat_chacha import ChaCha20_Poly1305
                cipher = ChaCha20_Poly1305.new(key=ctx.enc_key, nonce=nonce)
                core, tag = cipher_blob[:-16], cipher_blob[-16:]
                return cipher.decrypt_and_verify(core, tag, ctx.header_aad)
            except Exception:
                raise RuntimeError("Backend XChaCha20 indisponível.")

class AESCTRProcessor(ChunkProcessor):
    """Processador para AES-256-CTR + HMAC."""
    
    def __init__(self):
        self.hmac_state = None
    
    def init_hmac(self, ctx: CG2Context):
        """Inicializa HMAC com o header."""
        if ctx.mac_key:
            self.hmac_state = py_hmac.new(ctx.mac_key, digestmod="sha256")
            self.hmac_state.update(ctx.header_aad)
    
    def encrypt_chunk(self, chunk: bytes, index: int, ctx: CG2Context) -> bytes:
        if ctx.pad_block_size > 0:
            chunk = _pad(chunk, ctx.pad_block_size)
            
        iv = _derive_chunk_nonce(ctx.base_nonce, index)
        cipher = Cipher(algorithms.AES(ctx.enc_key), modes.CTR(iv))
        enc = cipher.encryptor()
        ct = enc.update(chunk) + enc.finalize()
        
        lb = struct.pack(">I", len(ct))
        payload = iv + lb + ct
        
        # Atualiza HMAC
        if self.hmac_state:
            self.hmac_state.update(lb)
            self.hmac_state.update(ct)
            
        return payload
    
    def decrypt_chunk(self, cipher_blob: bytes, nonce: bytes, index: int, ctx: CG2Context) -> bytes:
        iv = nonce
        cipher = Cipher(algorithms.AES(ctx.enc_key), modes.CTR(iv))
        dec = cipher.decryptor()
        plain = dec.update(cipher_blob) + dec.finalize()
        return plain
    
    def get_hmac_digest(self) -> bytes:
        """Obtém o digest HMAC final."""
        if self.hmac_state:
            return self.hmac_state.digest()
        return b""

# ════════════════════════════════════════════════════════════════════════════
#                           FOOTER HANDLERS
# ════════════════════════════════════════════════════════════════════════════

class FooterHandler(ABC):
    """Base abstrata para manipulação de rodapés."""
    
    @abstractmethod
    def write_footer(self, fout: BinaryIO, ctx: CG2Context, 
                    chunk_count: int, total_size: int) -> None:
        """Escreve rodapé no arquivo."""
        pass
    
    @abstractmethod
    def read_footer(self, fin: BinaryIO, ctx: CG2Context) -> Tuple[int, int, Optional[str]]:
        """Lê e valida rodapé. Retorna (chunk_count, total_size, extension)."""
        pass

class AEADFooterHandler(FooterHandler):
    """Handler de footer para modos AEAD."""
    
    def write_footer(self, fout: BinaryIO, ctx: CG2Context, 
                    chunk_count: int, total_size: int) -> None:
        # Escreve extensão cifrada (NAM0) se houver
        if ctx.original_extension:
            name_blob = self._pack_name_blob(ctx)
            fout.write(NAME_MAGIC)
            fout.write(name_blob)
        
        # Footer AEAD (detecção de truncamento + tamanho real)
        ft_key = _final_tag_key(ctx.master_key)
        final_payload = struct.pack(">IQ", chunk_count, total_size)
        nonce = b"\x00" * 12
        final_tag = AESGCM(ft_key).encrypt(nonce, final_payload, ctx.header_aad)
        
        fout.write(END_MAGIC)
        fout.write(struct.pack(">I", len(final_tag)))
        fout.write(final_tag)
    
    def read_footer(self, fin: BinaryIO, ctx: CG2Context, 
                   total_chunks_read: int, total_bytes_written: int) -> Tuple[int, int, Optional[str]]:
        """Lê footer AEAD e valida integridade."""
        ext_from_name = None
        
        while True:
            magic = fin.read(4)
            if not magic:
                raise ValueError("Footer ausente (arquivo possivelmente truncado)")
                
            if magic == NAME_MAGIC:
                # Lê extensão cifrada
                ext_from_name = self._unpack_name_blob(fin, ctx)
                continue
                
            if magic == END_MAGIC:
                # Lê e valida footer AEAD
                flen_b = fin.read(4)
                if len(flen_b) != 4:
                    raise ValueError("Footer truncado (len)")
                (flen,) = struct.unpack(">I", flen_b)
                blob = fin.read(flen)
                if len(blob) != flen:
                    raise ValueError("Footer truncado (blob)")
                
                ft_key = _final_tag_key(ctx.master_key)
                nonce = b"\x00" * 12
                payload = AESGCM(ft_key).decrypt(nonce, blob, ctx.header_aad)
                exp_chunks, exp_total = struct.unpack(">IQ", payload)
                
                if exp_chunks != total_chunks_read or exp_total > total_bytes_written:
                    raise ValueError("Footer inconsistente (contagem/tamanho)")
                
                # Rejeita bytes extras após o rodapé
                extra = fin.read(1)
                if extra:
                    raise ValueError("Dados extras após o rodapé (END0)")
                    
                return exp_chunks, exp_total, ext_from_name
            
            # Se não for NAME_MAGIC nem END_MAGIC, é um chunk length
            raise ValueError(f"Magic inválido no footer: {magic}")
    
    def _pack_name_blob(self, ctx: CG2Context) -> bytes:
        """Produz: nonce(12) | 4B (len) | AESGCM(k).encrypt(nonce, ext_utf8, aad)"""
        name_k = _name_key(ctx.master_key)
        nonce = os.urandom(12)
        blob = AESGCM(name_k).encrypt(nonce, ctx.original_extension.encode("utf-8", "ignore"), ctx.header_aad)
        return nonce + struct.pack(">I", len(blob)) + blob
    
    def _unpack_name_blob(self, f: BinaryIO, ctx: CG2Context) -> str:
        """Lê nonce(12) | 4B len | blob e retorna a extensão em texto."""
        name_k = _name_key(ctx.master_key)
        nonce = f.read(12)
        if len(nonce) != 12:
            raise ValueError("NAM0 truncado (nonce)")
        lb = f.read(4)
        if len(lb) != 4:
            raise ValueError("NAM0 truncado (len)")
        (blen,) = struct.unpack(">I", lb)
        blob = f.read(blen)
        if len(blob) != blen:
            raise ValueError("NAM0 truncado (blob)")
        pt = AESGCM(name_k).decrypt(nonce, blob, ctx.header_aad)
        return pt.decode("utf-8", "ignore")

class CTRFooterHandler(FooterHandler):
    """Handler de footer para AES-CTR + HMAC."""
    
    def __init__(self, processor: AESCTRProcessor):
        self.processor = processor
    
    def write_footer(self, fout: BinaryIO, ctx: CG2Context, 
                    chunk_count: int, total_size: int) -> None:
        # NAM0 autenticado pela HMAC global (se houver extensão)
        if ctx.original_extension:
            name_blob = self._pack_name_blob(ctx)
            fout.write(NAME_MAGIC)
            self.processor.hmac_state.update(NAME_MAGIC)
            fout.write(name_blob)
            self.processor.hmac_state.update(name_blob)
        
        # Tamanho real antes do TAG
        fout.write(SIZ_MAGIC)
        fout.write(struct.pack(">Q", total_size))
        self.processor.hmac_state.update(SIZ_MAGIC)
        self.processor.hmac_state.update(struct.pack(">Q", total_size))
        
        # TAG HMAC
        fout.write(TAG_MAGIC)
        fout.write(self.processor.get_hmac_digest())
    
    def read_footer(self, fin: BinaryIO, ctx: CG2Context, h: py_hmac.HMAC) -> Tuple[int, int, Optional[str]]:
        """Lê footer CTR e valida HMAC."""
        ext_from_name = None
        exp_total_from_footer = None
        
        while True:
            magic = fin.read(4)
            if not magic:
                raise ValueError("TAG ausente no fim do arquivo (CTR)")
                
            if magic == NAME_MAGIC:
                # NAM0 entra na HMAC
                h.update(NAME_MAGIC)
                name_k = _name_key(ctx.master_key)
                pos = fin.tell()
                
                # Lê componentes do NAM0
                nonce = fin.read(12)
                lb = fin.read(4)
                if len(nonce) != 12 or len(lb) != 4:
                    raise ValueError("NAM0 truncado (CTR)")
                (blen,) = struct.unpack(">I", lb)
                blob = fin.read(blen)
                if len(blob) != blen:
                    raise ValueError("NAM0 truncado (CTR)")
                    
                # Volta e usa helper para decifrar
                fin.seek(pos)
                ext_from_name = self._unpack_name_blob(fin, ctx)
                
                # Alimenta HMAC com bytes brutos
                h.update(nonce)
                h.update(lb)
                h.update(blob)
                continue
                
            if magic == SIZ_MAGIC:
                # Tamanho real (sem padding)
                sz_b = fin.read(8)
                if len(sz_b) != 8:
                    raise ValueError("SIZ0 truncado (CTR)")
                (exp_total_real,) = struct.unpack(">Q", sz_b)
                h.update(SIZ_MAGIC)
                h.update(sz_b)
                
                # Em seguida esperamos TAG0
                next_magic = fin.read(4)
                if next_magic != TAG_MAGIC:
                    raise ValueError("TAG0 ausente após SIZ0 (CTR)")
                tag = fin.read(32)
                if len(tag) != 32:
                    raise ValueError("TAG truncada (CTR)")
                if not py_hmac.compare_digest(h.digest(), tag):
                    raise ValueError("HMAC inválido (arquivo corrompido ou senha incorreta)")
                    
                exp_total_from_footer = exp_total_real
                
                # Rejeita bytes extras após o TAG
                extra = fin.read(1)
                if extra:
                    raise ValueError("Dados extras após o TAG0 (CTR)")
                break
                
            if magic == TAG_MAGIC:
                # TAG sem SIZ0 (formato legado)
                tag = fin.read(32)
                if len(tag) != 32:
                    raise ValueError("TAG truncada (CTR)")
                if not py_hmac.compare_digest(h.digest(), tag):
                    raise ValueError("HMAC inválido (arquivo corrompido ou senha incorreta)")
                    
                # Rejeita bytes extras
                extra = fin.read(1)
                if extra:
                    raise ValueError("Dados extras após o TAG0 (CTR)")
                break
                
            # Chunk normal - volta 4 bytes
            fin.seek(fin.tell() - 4)
            return 0, exp_total_from_footer or 0, ext_from_name
            
        return 0, exp_total_from_footer or 0, ext_from_name
    
    def _pack_name_blob(self, ctx: CG2Context) -> bytes:
        """Produz NAM0 para CTR."""
        name_k = _name_key(ctx.master_key)
        nonce = os.urandom(12)
        blob = AESGCM(name_k).encrypt(nonce, ctx.original_extension.encode("utf-8", "ignore"), ctx.header_aad)
        return nonce + struct.pack(">I", len(blob)) + blob
    
    def _unpack_name_blob(self, f: BinaryIO, ctx: CG2Context) -> str:
        """Lê NAM0 para CTR."""
        name_k = _name_key(ctx.master_key)
        nonce = f.read(12)
        if len(nonce) != 12:
            raise ValueError("NAM0 truncado (nonce)")
        lb = f.read(4)
        if len(lb) != 4:
            raise ValueError("NAM0 truncado (len)")
        (blen,) = struct.unpack(">I", lb)
        blob = f.read(blen)
        if len(blob) != blen:
            raise ValueError("NAM0 truncado (blob)")
        pt = AESGCM(name_k).decrypt(nonce, blob, ctx.header_aad)
        return pt.decode("utf-8", "ignore")

# ════════════════════════════════════════════════════════════════════════════
#                         MAIN ORCHESTRATORS
# ════════════════════════════════════════════════════════════════════════════

class CG2Encryptor:
    """Orquestrador principal de criptografia CG2."""
    
    def __init__(self, algorithm: str, profile: SecurityProfile):
        self.algorithm = algorithm
        self.profile = profile
        self.processor = self._create_processor(algorithm)
        self.footer_handler = self._create_footer_handler()
    
    def encrypt(
        self,
        in_path: Path,
        out_path: Path,
        password: bytes,
        exp_ts: Optional[int] = None,
        pad_block: int = 0,
        progress_cb: Optional[Callable[[int], None]] = None
    ) -> Path:
        """Criptografa arquivo para formato CG2."""
        
        # Garante extensão .cg2
        if out_path.suffix.lower() != CG2_EXT:
            out_path = out_path.with_suffix(CG2_EXT)
        
        # Prepara contexto
        ctx = self._prepare_context(in_path, password, pad_block, exp_ts)
        
        # Inicializa HMAC se CTR
        if isinstance(self.processor, AESCTRProcessor):
            self.processor.init_hmac(ctx)
        
        total_real = 0
        idx = 0
        
        with in_path.open("rb") as fin, out_path.open("wb") as fout:
            # Escreve header (AAD)
            fout.write(ctx.header_aad)
            
            # Processa chunks
            while True:
                pt = fin.read(CHUNK_SIZE)
                if not pt:
                    break
                    
                total_real += len(pt)
                
                # Encripta chunk
                payload = self.processor.encrypt_chunk(pt, idx, ctx)
                fout.write(payload)
                
                idx += 1
                if progress_cb:
                    progress_cb(total_real)
            
            # Escreve footer
            self.footer_handler.write_footer(fout, ctx, idx, total_real)
        
        logger.info(
            "Encrypted CG2 %s → %s (%s, chunks=%d, real=%d)",
            in_path.name,
            out_path.name,
            self.algorithm,
            idx,
            total_real,
        )
        return out_path
    
    def _prepare_context(
        self,
        in_path: Path,
        password: bytes,
        pad_block: int,
        exp_ts: Optional[int]
    ) -> CG2Context:
        """Prepara contexto de criptografia."""
        # KDF e chaves
        salt = os.urandom(16)
        kdf_params = {"name": "argon2id", "salt": salt.hex(), **ARGON_PARAMS[self.profile]}
        mk = derive_key(password, kdf_params)
        
        # Nonce/IV base
        if self.algorithm == "AES-256-GCM":
            base_nonce = os.urandom(12)
        elif self.algorithm == "XChaCha20-Poly1305":
            base_nonce = os.urandom(24)
        elif self.algorithm == "ChaCha20-Poly1305":
            base_nonce = os.urandom(12)
        elif self.algorithm == "AES-256-CTR":
            base_nonce = os.urandom(16)
        else:
            raise ValueError(f"Algoritmo não suportado: {self.algorithm}")
        
        # Header
        header = CG2Header(
            version=4,
            alg=self.algorithm,
            kdf=kdf_params,
            nonce=base_nonce,
            exp_ts=exp_ts
        )
        aad = header.pack()
        
        # Chaves
        enc_key = mk
        mac_key = None
        if self.algorithm == "AES-256-CTR":
            enc_key, mac_key = _split_enc_mac_keys(mk)
        
        return CG2Context(
            algorithm=self.algorithm,
            master_key=mk,
            enc_key=enc_key,
            mac_key=mac_key,
            base_nonce=base_nonce,
            header_aad=aad,
            salt=salt,
            profile=self.profile,
            pad_block_size=pad_block,
            original_extension=in_path.suffix or "",
            expiration_ts=exp_ts
        )
    
    def _create_processor(self, algorithm: str) -> ChunkProcessor:
        """Factory para processador de chunks."""
        if algorithm == "AES-256-GCM":
            return AESGCMProcessor()
        elif algorithm == "ChaCha20-Poly1305":
            return ChaCha20Processor()
        elif algorithm == "XChaCha20-Poly1305":
            return XChaCha20Processor()
        elif algorithm == "AES-256-CTR":
            return AESCTRProcessor()
        else:
            raise ValueError(f"Algoritmo não suportado: {algorithm}")
    
    def _create_footer_handler(self) -> FooterHandler:
        """Factory para handler de footer."""
        if self.algorithm in AEAD_SET:
            return AEADFooterHandler()
        else:
            return CTRFooterHandler(self.processor)

class CG2Decryptor:
    """Orquestrador principal de descriptografia CG2."""
    
    def __init__(self, header: CG2Header, header_aad: bytes):
        self.header = header
        self.header_aad = header_aad
        self.processor = self._create_processor(header.alg)
        self.footer_handler = self._create_footer_handler()
    
    def decrypt(
        self,
        in_path: Path,
        out_path: Path,
        password: bytes,
        offset: int,
        verify_only: bool = False,
        progress_cb: Optional[Callable[[int], None]] = None
    ) -> Path | bool:
        """Descriptografa arquivo CG2."""
        
        # Verifica expiração
        if self.header.exp_ts is not None and time.time() > self.header.exp_ts:
            raise PermissionError("File expired")
        
        # Deriva chaves
        mk = derive_key(password, self.header.kdf)
        enc_key = mk
        mac_key = None
        if self.header.alg == "AES-256-CTR":
            enc_key, mac_key = _split_enc_mac_keys(mk)
        
        ctx = CG2Context(
            algorithm=self.header.alg,
            master_key=mk,
            enc_key=enc_key,
            mac_key=mac_key,
            base_nonce=self.header.nonce,
            header_aad=self.header_aad,
            salt=b"",  # não usado em decrypt
            profile=SecurityProfile.BALANCED,  # não usado em decrypt
            pad_block_size=0,
            original_extension="",
            expiration_ts=self.header.exp_ts
        )
        
        total_written = 0
        idx = 0
        first_block = True
        out_f = None
        exp_total_from_footer = None
        ext_from_name = None
        
        def _ensure_open_with_ext_from(pt: bytes):
            nonlocal out_f, out_path
            if verify_only or out_f is not None:
                return
            # Tentativa inicial por magic
            ext = _guess_extension(pt) or ""
            if out_path.suffix == "" and ext:
                out_path = out_path.with_suffix(ext)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_f = out_path.open("wb")
        
        with in_path.open("rb") as f:
            f.seek(offset)
            try:
                if self.header.alg in AEAD_SET:
                    # Loop de chunks AEAD
                    while True:
                        len_bytes = f.read(4)
                        if not len_bytes:
                            raise ValueError("Footer ausente (arquivo possivelmente truncado)")
                        
                        # Verifica se é magic de footer
                        if len_bytes in (NAME_MAGIC, END_MAGIC):
                            f.seek(f.tell() - 4)
                            exp_chunks, exp_total_from_footer, ext_from_name = self.footer_handler.read_footer(
                                f, ctx, idx, total_written
                            )
                            break
                        
                        # Chunk normal
                        (clen,) = struct.unpack(">I", len_bytes)
                        ct = f.read(clen)
                        if len(ct) != clen:
                            raise ValueError("Payload truncado/corrompido (AEAD)")
                        
                        nonce = _derive_chunk_nonce(self.header.nonce, idx)
                        pt = self.processor.decrypt_chunk(ct, nonce, idx, ctx)
                        
                        if first_block:
                            _ensure_open_with_ext_from(pt)
                            first_block = False
                        
                        total_written += len(pt)
                        if progress_cb:
                            progress_cb(total_written)
                        if not verify_only and out_f:
                            out_f.write(pt)
                        idx += 1
                    
                else:
                    # AES-CTR + HMAC
                    h = py_hmac.new(mac_key, digestmod="sha256")
                    h.update(self.header_aad)
                    
                    # Inicializa processador CTR
                    if isinstance(self.processor, AESCTRProcessor):
                        self.processor.init_hmac(ctx)
                    
                    while True:
                        len_bytes = f.read(4)
                        if not len_bytes:
                            raise ValueError("TAG ausente no fim do arquivo (CTR)")
                        
                        # Verifica magics de footer
                        if len_bytes in (NAME_MAGIC, SIZ_MAGIC, TAG_MAGIC):
                            f.seek(f.tell() - 4)
                            _, exp_total_from_footer, ext_from_name = self.footer_handler.read_footer(
                                f, ctx, h
                            )
                            break
                        
                        # Chunk normal
                        (clen,) = struct.unpack(">I", len_bytes)
                        ct = f.read(clen)
                        if len(ct) != clen:
                            raise ValueError("Payload truncado/corrompido (CTR)")
                        
                        h.update(len_bytes)
                        h.update(ct)
                        
                        iv = _derive_chunk_nonce(self.header.nonce, idx)
                        pt = self.processor.decrypt_chunk(ct, iv, idx, ctx)
                        
                        if first_block:
                            _ensure_open_with_ext_from(pt)
                            first_block = False
                        
                        total_written += len(pt)
                        if progress_cb:
                            progress_cb(total_written)
                        if not verify_only and out_f:
                            out_f.write(pt)
                        idx += 1
                        
            finally:
                # Garante fechamento do arquivo
                if not verify_only and out_f is not None and not out_f.closed:
                    with contextlib.suppress(Exception):
                        out_f.close()
        
        if verify_only:
            return True
            
        # Trunca se necessário (padding)
        if not verify_only and out_f is not None and exp_total_from_footer is not None:
            out_f.flush()
            out_f.close()
            if exp_total_from_footer < total_written:
                with out_path.open("rb+") as tf:
                    tf.truncate(exp_total_from_footer)
            out_f = None
        
        # Renomeia com extensão correta se NAM0 presente
        if not verify_only and ext_from_name:
            want = ext_from_name if ext_from_name.startswith(".") else f".{ext_from_name}"
            cur = out_path.suffix
            if want and cur.lower() != want.lower():
                newp = out_path.with_suffix(want)
                try:
                    os.replace(out_path, newp)
                    out_path = newp
                except Exception:
                    pass
        
        # Garante criação do arquivo quando plaintext tem 0 bytes
        if not verify_only and not out_path.exists():
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.touch()
        
        logger.info(
            "Decrypted CG2 %s → %s (%s, chunks=%d)",
            in_path.name,
            out_path.name,
            self.header.alg,
            idx
        )
        return out_path
    
    def _create_processor(self, algorithm: str) -> ChunkProcessor:
        """Factory para processador de chunks."""
        if algorithm == "AES-256-GCM":
            return AESGCMProcessor()
        elif algorithm == "ChaCha20-Poly1305":
            return ChaCha20Processor()
        elif algorithm == "XChaCha20-Poly1305":
            return XChaCha20Processor()
        elif algorithm == "AES-256-CTR":
            return AESCTRProcessor()
        else:
            raise ValueError(f"Algoritmo não suportado: {algorithm}")
    
    def _create_footer_handler(self) -> FooterHandler:
        """Factory para handler de footer."""
        if self.header.alg in AEAD_SET:
            return AEADFooterHandler()
        else:
            return CTRFooterHandler(self.processor)

# ════════════════════════════════════════════════════════════════════════════
#                       COMPATIBILITY FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════

def encrypt_to_cg2(
    in_path: str | Path,
    out_path: str | Path,
    password: bytes,
    alg: str,
    profile: SecurityProfile = SecurityProfile.BALANCED,
    exp_ts: int | None = None,
    *,
    progress_cb: Callable[[int], None] | None = None,
    pad_block: int = 0,
) -> Path:
    """
    Criptografa em streaming para CG2 com header autenticado e rodapé.
    Mantém assinatura idêntica à original para total compatibilidade.
    """
    in_path = Path(in_path)
    out_path = Path(out_path)
    
    encryptor = CG2Encryptor(alg, profile)
    return encryptor.encrypt(
        in_path,
        out_path,
        password,
        exp_ts=exp_ts,
        pad_block=pad_block,
        progress_cb=progress_cb
    )

def decrypt_from_cg2(
    in_path: str | Path,
    out_path: str | Path,
    password: bytes,
    verify_only: bool = False,
    *,
    progress_cb: Callable[[int], None] | None = None,
) -> Path | bool:
    """
    Descriptografa/verifica CG2 (streaming).
    Mantém assinatura idêntica à original para total compatibilidade.
    """
    in_path = Path(in_path)
    out_path = Path(out_path)
    
    # Lê header
    hdr, aad, off, _ext_legacy_ignored = read_header(in_path)
    
    decryptor = CG2Decryptor(hdr, aad)
    return decryptor.decrypt(
        in_path,
        out_path,
        password,
        offset=off,
        verify_only=verify_only,
        progress_cb=progress_cb
      )
