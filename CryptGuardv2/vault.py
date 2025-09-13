#!/usr/bin/env python3
"""vault_v2.py – Vault 3.x refatorado com correções de segurança

Mudanças principais:
    • Removido pickle - usa JSON seguro
    • Corrigido path traversal
    • Proteção contra timing attacks
    • Estrutura modular com separação de responsabilidades
    • Gestão de memória otimizada com streaming
    • Tipagem completa com dataclasses
    • GUI desacoplada da lógica
    • Backends simplificados
"""

from __future__ import annotations

import base64
import contextlib
import ctypes
import gzip
import hashlib
import hmac
import io
import json
import logging
import multiprocessing
import os
import platform
import secrets
import stat
import struct
import sys
import tempfile
import threading
import time
import warnings
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import Enum
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Protocol, Tuple, TypeVar
from crypto_core.secure_bytes import SecureBytes

# ─── Verificação de dependências com versões mínimas ───────────────────────
REQUIRED_DEPS = {
    "cryptography": "41.0.0",
    "argon2-cffi": "23.1.0", 
    "psutil": "5.9.0",
    "PySide6": "6.6.0"
}

def check_dependencies():
    """Verifica dependências com versões mínimas."""
    missing = []
    for pkg, min_version in REQUIRED_DEPS.items():
        try:
            IMPORT_NAME = {"argon2-cffi": "argon2"}  # adicione isso
            mod = __import__(IMPORT_NAME.get(pkg, pkg.replace("-", "_")))
            # Verifica versão se disponível
            if hasattr(mod, "__version__"):
                try:
                    from packaging import version
                    if version.parse(mod.__version__) < version.parse(min_version):
                        missing.append(f"{pkg}>={min_version}")
                except Exception:
                    # If 'packaging' is not available, skip strict version check
                    pass
        except ImportError:
            missing.append(f"{pkg}>={min_version}")
    
    if missing:
        print(f"Dependências faltando ou desatualizadas: {', '.join(missing)}")
        print(f"→ pip install -U {' '.join(missing)}")
        sys.exit(1)

check_dependencies()

import argon2.low_level as _argon2
import psutil
from argon2.low_level import Type as _ArgonType
from cryptography.exceptions import InvalidTag
from crypto_core.logger import SecureFormatter
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Backend XChaCha unificado - prioriza cryptography
try:
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
    XCHACHA_AVAILABLE = True
except ImportError:
    XChaCha20Poly1305 = None
    XCHACHA_AVAILABLE = False
    # Fallback para PyNaCl se necessário
    try:
        from nacl.bindings import (
            crypto_aead_xchacha20poly1305_ietf_decrypt as nacl_xch_decrypt,
            crypto_aead_xchacha20poly1305_ietf_encrypt as nacl_xch_encrypt,
        )
        NACL_AVAILABLE = True
    except ImportError:
        NACL_AVAILABLE = False

# Qt imports
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

# Windows-specific imports
if platform.system() == "Windows":
    try:
        import ntsecuritycon as nsec
        import win32api
        import win32security
        WIN32_AVAILABLE = True
    except ImportError:
        WIN32_AVAILABLE = False

# ════════════════════════════════════════════════════════════════════════════
#                              TYPE DEFINITIONS
# ════════════════════════════════════════════════════════════════════════════

# Coloque no topo de vault.py, antes de usar:
HEADER_FMT = ">4sB16s24sHIB"
HEADER_STRUCT = struct.Struct(HEADER_FMT)
HEADER_LEN = HEADER_STRUCT.size          # 52
# Usar literal para evitar NameError antes da definição de Config
HMAC_LEN = 32  # Igual a Config.HMAC_SIZE
TOTAL_HEADER = HEADER_LEN + HMAC_LEN     # 84

T = TypeVar("T")

class StorageBackend(Protocol):
    """Interface para backends de storage."""
    def save(self, data: bytes) -> None: ...
    def load(self) -> bytes: ...

@dataclass
class KDFParams:
    """Parâmetros Argon2 tipados."""
    time_cost: int
    memory_cost: int
    parallelism: int
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> KDFParams:
        return cls(**data)

@dataclass
class VaultHeader:
    """Header tipado do vault."""
    magic: bytes
    version: int
    salt: bytes
    nonce: bytes
    kdf: KDFParams
    
    def pack(self, hmac_key: bytes) -> bytes:
        """Serializa header com HMAC."""
        hdr = struct.pack(
            ">4sB16s24sHIB",
            self.magic,
            self.version,
            self.salt,
            self.nonce,
            self.kdf.time_cost,
            self.kdf.memory_cost,
            self.kdf.parallelism
        )
        mac = hmac.new(hmac_key, hdr, hashlib.sha256).digest()
        return hdr + mac
    
    @classmethod
    def unpack(cls, data: bytes, hmac_key: bytes) -> VaultHeader:
        if len(data) < TOTAL_HEADER:
            raise CorruptVault("Header too small")
        hdr = data[:HEADER_LEN]
        mac = data[HEADER_LEN:TOTAL_HEADER]
        if not hmac.compare_digest(mac, hmac.new(hmac_key, hdr, hashlib.sha256).digest()):
            raise WrongPassword("Senha incorreta")
        magic, ver, salt, nonce, t, m, p = HEADER_STRUCT.unpack(hdr)
        return cls(magic=magic, version=ver, salt=salt, nonce=nonce, kdf=KDFParams(t, m, p))

@dataclass
class VaultEntry:
    """Entrada individual no vault."""
    label: str
    data: bytes
    created_at: float
    size: int
    checksum: str
    
    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "data": base64.b64encode(self.data).decode(),
            "created_at": self.created_at,
            "size": self.size,
            "checksum": self.checksum
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> VaultEntry:
        return cls(
            label=data["label"],
            data=base64.b64decode(data["data"]),
            created_at=data.get("created_at", time.time()),
            size=data.get("size", 0),
            checksum=data.get("checksum", "")
        )

# ════════════════════════════════════════════════════════════════════════════
#                           CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════

class Config:
    """Configuração centralizada do vault."""
    MAGIC: bytes = b"VLT3"
    VERSION: int = 3
    SALT_SIZE: int = 16
    NONCE_SIZE: int = 24
    KEY_SIZE: int = 32
    HMAC_SIZE: int = 32
    MAX_VAULT_SIZE: int = 128 * 2**20  # 128 MB
    MIN_MASTER_PW_LEN: int = 12
    MAX_LABEL_LENGTH: int = 255
    CHUNK_SIZE: int = 64 * 1024  # 64KB para streaming
    
    # Parâmetros Argon2 padrão
    ARGON_TIME = 6
    ARGON_MEM = 2**20  # 1 GiB em KiB
    ARGON_PARALLEL = min(8, multiprocessing.cpu_count() or 2)
    
    # Rate limiting
    MAX_ATTEMPTS = 5
    LOCKOUT_WINDOW = 300  # 5 minutos
    
    # Paths
    BASE_DIR = Path.home() / ".cryptguard"
    INI_PATH = BASE_DIR / "vault.ini"
    LOG_PATH = BASE_DIR / "vault.log"
    
    @classmethod
    def default_vault_path(cls) -> Path:
        """Retorna o caminho padrão do arquivo de vault."""
        if platform.system() == "Windows":
            appdata = os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
            p = Path(appdata) / "CryptGuard" / "vault3.dat"
        else:
            p = cls.BASE_DIR / "vault3.dat"
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    
    @classmethod
    def get_kdf_params(cls) -> KDFParams:
        """Obtém parâmetros KDF calibrados ou padrão."""
        import configparser
        
        if cls.INI_PATH.exists():
            try:
                cp = configparser.ConfigParser()
                cp.read(cls.INI_PATH)
                return KDFParams(
                    time_cost=cp.getint("kdf", "time_cost"),
                    memory_cost=cp.getint("kdf", "memory_cost"),
                    parallelism=cp.getint("kdf", "parallelism")
                )
            except Exception:
                pass
        
        # Calibra se não existir
        return cls._calibrate_kdf()
    
    @classmethod
    def _calibrate_kdf(cls, target_ms: int = 1000) -> KDFParams:
        """Calibra Argon2 para o hardware atual."""
        import configparser
        
        salt = secrets.token_bytes(16)
        pw = b"benchmark"
        mem = max(2**19, cls.ARGON_MEM)
        t = max(4, cls.ARGON_TIME)
        par = cls.ARGON_PARALLEL
        vmax = psutil.virtual_memory().total * 0.75
        
        while True:
            if mem * 1024 > vmax:
                break
            t0 = time.perf_counter()
            _argon2.hash_secret_raw(pw, salt, t, mem, par, 32, _ArgonType.ID)
            dur = (time.perf_counter() - t0) * 1000
            if dur >= target_ms or mem * 2 * 1024 > vmax:
                break
            mem <<= 1
        
        params = KDFParams(t, mem, par)
        
        # Salva calibração
        cp = configparser.ConfigParser()
        cp["kdf"] = params.to_dict()
        cls.INI_PATH.parent.mkdir(exist_ok=True)
        with open(cls.INI_PATH, "w") as f:
            cp.write(f)
        os.chmod(cls.INI_PATH, 0o600)
        
        return params

# ════════════════════════════════════════════════════════════════════════════
#                              EXCEPTIONS
# ════════════════════════════════════════════════════════════════════════════

class VaultError(Exception):
    """Base para erros do vault."""
    pass

class WrongPassword(VaultError):
    """Senha incorreta."""
    pass

class CorruptVault(VaultError):
    """Vault corrompido."""
    pass

class VaultLocked(VaultError):
    """Vault bloqueado por rate limiting."""
    pass

# ════════════════════════════════════════════════════════════════════════════
#                           SECURITY COMPONENTS
# ════════════════════════════════════════════════════════════════════════════

class SecurityWarning(UserWarning):
    """Aviso de segurança com logging."""
    def __init__(self, msg: str, category: str, severity: str = "medium"):
        super().__init__(msg)
        log = _get_logger()
        level = {"critical": "critical", "high": "error", "medium": "warning"}.get(severity, "info")
        getattr(log, level)(f"[{severity.upper()}] {category}: {msg}")

class ProcessProtection:
    """Proteção de processo (best-effort)."""
    
    _applied = False
    
    @classmethod
    def apply(cls):
        if cls._applied:
            return
        cls._applied = True
        
        # Desabilita core dumps
        if hasattr(os, "setrlimit"):
            try:
                import resource
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except Exception:
                pass
        
        # Windows DEP
        if platform.system() == "Windows":
            try:
                kernel32 = ctypes.WinDLL("kernel32")
                kernel32.SetProcessDEPPolicy(1)
            except Exception:
                pass
        
        # Detecta debugger
        if sys.gettrace() is not None:
            warnings.warn(
                SecurityWarning("Debugger detectado", "debug", "high"),
                stacklevel=2
            )

class SecureMemory:
    """Gerenciamento seguro de memória sensível."""
    
    def __init__(self, data: str | bytes | bytearray):
        if isinstance(data, str):
            data = data.encode()
        self._buf = bytearray(data)
        self._lock_pages()
    
    def _lock_pages(self):
        """Tenta fazer mlock/VirtualLock nas páginas."""
        size = len(self._buf)
        ok = False
        
        try:
            addr = ctypes.addressof(ctypes.c_char.from_buffer(self._buf))
            
            if platform.system() == "Windows" and hasattr(ctypes, "windll"):
                ok = bool(ctypes.windll.kernel32.VirtualLock(
                    ctypes.c_void_p(addr), 
                    ctypes.c_size_t(size)
                ))
            else:
                # Linux/BSD/macOS
                for lib_name in ("libc.so.6", "libSystem.B.dylib"):
                    try:
                        libc = ctypes.CDLL(lib_name)
                        ok = (libc.mlock(addr, ctypes.c_size_t(size)) == 0)
                        if ok:
                            break
                    except Exception:
                        continue
        except Exception:
            pass
        
        if not ok:
            warnings.warn("mlock/VirtualLock falhou – páginas não protegidas", stacklevel=2)
    
    def bytes(self) -> bytes:
        return bytes(self._buf)
    
    def clear(self):
        """Zera memória de forma segura."""
        # Múltiplas passadas para dificultar recuperação
        for pattern in (b"\xff", b"\x00", b"\x55", b"\xaa", b"\x00"):
            self._buf[:] = pattern * len(self._buf)
        
        # Tenta SecureZeroMemory no Windows
        if platform.system() == "Windows":
            try:
                addr = ctypes.addressof(ctypes.c_char.from_buffer(self._buf))
                ctypes.windll.kernel32.RtlSecureZeroMemory(addr, len(self._buf))
            except Exception:
                pass
    
    def __del__(self):
        self.clear()

class RateLimiter:
    """Rate limiter thread-safe com proteção contra timing attacks."""
    
    def __init__(self, window: int = 300, threshold: int = 5):
        self.window = window
        self.threshold = threshold
        self.attempts: Dict[str, List[float]] = {}
        self.lock = threading.RLock()
    
    def check(self, identifier: str = "default"):
        """Verifica se operação é permitida."""
        with self.lock:
            now = time.time()
            
            # Limpa tentativas antigas
            if identifier in self.attempts:
                self.attempts[identifier] = [
                    t for t in self.attempts[identifier] 
                    if now - t < self.window
                ]
            
            # Verifica limite
            attempts = self.attempts.get(identifier, [])
            if len(attempts) >= self.threshold:
                remaining = self.window - (now - attempts[-self.threshold])
                raise VaultLocked(f"Rate limited - aguarde {int(remaining)}s")
    
    def record_failure(self, identifier: str = "default"):
        """Registra falha com delay constante para evitar timing attacks."""
        # Delay aleatório para mascarar timing
        time.sleep(secrets.randbelow(100) / 1000)  # 0-100ms
        
        with self.lock:
            now = time.time()
            if identifier not in self.attempts:
                self.attempts[identifier] = []
            self.attempts[identifier].append(now)
    
    def clear(self, identifier: str = "default"):
        """Limpa tentativas após sucesso."""
        with self.lock:
            self.attempts.pop(identifier, None)

# ════════════════════════════════════════════════════════════════════════════
#                           CRYPTO COMPONENTS
# ════════════════════════════════════════════════════════════════════════════

def derive_keys(password: SecureMemory, salt: bytes, params: KDFParams) -> Tuple[bytes, bytes]:
    """Deriva chaves de criptografia e HMAC via Argon2id + HKDF."""
    master = _argon2.hash_secret_raw(
        password.bytes(),
        salt,
        params.time_cost,
        params.memory_cost,
        params.parallelism,
        64,
        _ArgonType.ID
    )
    
    # HKDF para separar chaves
    outer = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"Vault split v3"
    ).derive(master)
    
    # Limpa master key
    master = bytearray(master)
    for i in range(len(master)):
        master[i] = 0
    
    return outer[:32], outer[32:]  # enc_key, hmac_key

class CryptoEngine:
    """Engine de criptografia unificado."""
    
    def __init__(self, enc_key: bytes):
        self.key = bytearray(enc_key)
        
        # Seleciona backend disponível
        if XCHACHA_AVAILABLE:
            self.backend = "xchacha20"
            self.nonce_len = 24
        elif NACL_AVAILABLE:
            self.backend = "nacl"
            self.nonce_len = 24
        else:
            self.backend = "chacha20"
            self.nonce_len = 12
    
    def gen_nonce(self) -> bytes:
        """Gera nonce apropriado ao backend em uso."""
        if self.backend in ("xchacha20", "nacl"):
            return secrets.token_bytes(24)
        # ChaCha20-Poly1305 IETF: 12 bytes
        return secrets.token_bytes(12)

    def encrypt_with_nonce(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Cifra usando um nonce fornecido e retorna apenas o ciphertext."""
        if self.backend == "xchacha20":
            return XChaCha20Poly1305(bytes(self.key)).encrypt(nonce, plaintext, aad)
        elif self.backend == "nacl":
            return nacl_xch_encrypt(plaintext, aad, nonce, bytes(self.key))
        else:
            # Para ChaCha20-Poly1305 (12B), usa os 12 primeiros bytes do nonce
            use_nonce = nonce[:12] if len(nonce) >= 12 else nonce
            return ChaCha20Poly1305(bytes(self.key)).encrypt(use_nonce, plaintext, aad)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        """Encripta dados retornando (nonce, ciphertext)."""
        # Gera nonce e aplica compatibilidade de armazenamento (24B no header)
        raw_nonce = self.gen_nonce()
        stored_nonce = (
            raw_nonce + (b"\x00" * 12)
            if self.backend == "chacha20" and len(raw_nonce) == 12
            else raw_nonce
        )
        ct = self.encrypt_with_nonce(stored_nonce, plaintext, aad)
        return stored_nonce, ct
    
    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """Decripta dados."""
        try:
            if self.backend == "xchacha20":
                return XChaCha20Poly1305(bytes(self.key)).decrypt(nonce, ciphertext, aad)
            elif self.backend == "nacl":
                return nacl_xch_decrypt(ciphertext, aad, nonce, bytes(self.key))
            else:
                # Usa apenas os primeiros 12 bytes do nonce
                return ChaCha20Poly1305(bytes(self.key)).decrypt(nonce[:12], ciphertext, aad)
        except Exception:
            raise InvalidTag("Falha na verificação de autenticidade")
    
    def clear(self):
        """Limpa chave da memória."""
        for i in range(len(self.key)):
            self.key[i] = 0
    
    def __del__(self):
        self.clear()

# ════════════════════════════════════════════════════════════════════════════
#                            COMPRESSION
# ════════════════════════════════════════════════════════════════════════════

class StreamingCompressor:
    """Compressão com streaming para economia de memória."""
    
    @staticmethod
    def compress(data: bytes, chunk_size: int = Config.CHUNK_SIZE) -> bytes:
        """Comprime dados em chunks."""
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6) as gz:
            for i in range(0, len(data), chunk_size):
                gz.write(data[i:i + chunk_size])
        return buf.getvalue()
    
    @staticmethod
    def decompress(data: bytes, chunk_size: int = Config.CHUNK_SIZE) -> bytes:
        """Descomprime dados em chunks."""
        out = io.BytesIO()
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            while True:
                chunk = gz.read(chunk_size)
                if not chunk:
                    break
                out.write(chunk)
        return out.getvalue()

# ════════════════════════════════════════════════════════════════════════════
#                          SERIALIZATION
# ════════════════════════════════════════════════════════════════════════════

class SecureSerializer:
    """Serialização segura sem pickle."""
    
    @staticmethod
    def serialize(entries: Dict[str, VaultEntry]) -> bytes:
        """Serializa entradas para JSON."""
        data = {
            "version": 2,
            "entries": {
                label: entry.to_dict() 
                for label, entry in entries.items()
            }
        }
        return json.dumps(data, separators=(",", ":")).encode()
    
    @staticmethod
    def deserialize(data: bytes) -> Dict[str, VaultEntry]:
        """Deserializa JSON para entradas."""
        try:
            obj = json.loads(data)
            
            # Compatibilidade com formato antigo (base64 strings)
            if "entries" not in obj:
                # Formato legado: {"label": "base64_data"}
                return {
                    SecureSerializer._sanitize_label(label): VaultEntry(
                        label=SecureSerializer._sanitize_label(label),
                        data=base64.b64decode(b64_str),
                        created_at=time.time(),
                        size=len(base64.b64decode(b64_str)),
                        checksum=hashlib.sha256(base64.b64decode(b64_str)).hexdigest()
                    )
                    for label, b64_str in obj.items()
                }
            
            # Formato novo
            return {
                SecureSerializer._sanitize_label(label): VaultEntry.from_dict(entry_dict)
                for label, entry_dict in obj["entries"].items()
            }
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            raise CorruptVault(f"Falha ao deserializar vault: {e}")
    
    @staticmethod
    def _sanitize_label(label: str) -> str:
        """Sanitiza label para prevenir path traversal."""
        # Remove caracteres perigosos
        dangerous = ["../", "..\\", "/", "\\", ":", "*", "?", '"', "<", ">", "|", "\x00"]
        sanitized = label
        for char in dangerous:
            sanitized = sanitized.replace(char, "_")
        
        # Limita tamanho
        if len(sanitized) > Config.MAX_LABEL_LENGTH:
            sanitized = sanitized[:Config.MAX_LABEL_LENGTH]
        
        # Não permite nomes especiais do Windows
        reserved = ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"]
        if sanitized.upper() in reserved:
            sanitized = f"_{sanitized}"
        
        return sanitized or "unnamed"

# ════════════════════════════════════════════════════════════════════════════
#                            STORAGE
# ════════════════════════════════════════════════════════════════════════════

class AtomicStorageBackend:
    """Backend de storage com escrita atômica e WAL."""
    
    def __init__(self, path: Path):
        self.path = path
        self.wal = path.with_suffix(".wal")
        self.bak = path.with_suffix(".bak")
        self.lock = threading.RLock()
    
    def save(self, data: bytes):
        """Salva dados atomicamente."""
        with self.lock:
            # Escreve WAL primeiro
            self._write_wal(data)
            
            # Escreve arquivo temporário
            fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".tmp_")
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                
                # Backup do arquivo atual se existir
                if self.path.exists():
                    self.path.replace(self.bak)
                
                # Move temporário para final
                Path(tmp).replace(self.path)
                
                # Remove WAL após sucesso
                self.wal.unlink(missing_ok=True)
                
                # Define permissões restritivas
                self._set_permissions(self.path)
                
            except Exception as e:
                Path(tmp).unlink(missing_ok=True)
                raise CorruptVault(f"Falha ao salvar vault: {e}")
    
    def load(self) -> bytes:
        """Carrega dados com recovery de WAL."""
        with self.lock:
            # Verifica WAL primeiro
            if self.wal.exists():
                warnings.warn(
                    SecurityWarning("WAL encontrado - recovery automático", "storage", "high"),
                    stacklevel=2
                )
                data = self.wal.read_bytes()
                self.save(data)  # Completa transação pendente
                return data
            
            # Carrega arquivo principal
            if not self.path.exists():
                return b""
            
            data = self.path.read_bytes()
            if len(data) == 0:
                # Tenta backup se arquivo principal está vazio
                if self.bak.exists():
                    return self.bak.read_bytes()
                raise CorruptVault("Arquivo vault vazio")
            
            return data
    
    def _write_wal(self, data: bytes):
        """Escreve Write-Ahead Log."""
        with self.wal.open("wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    
    def _set_permissions(self, path: Path):
        """Define permissões restritivas no arquivo."""
        try:
            if platform.system() != "Windows":
                path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            elif WIN32_AVAILABLE:
                # Windows ACL
                sd = win32security.GetFileSecurity(
                    str(path),
                    win32security.DACL_SECURITY_INFORMATION
                )
                dacl = win32security.ACL()
                user, _, _ = win32security.LookupAccountName("", win32api.GetUserName())
                dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    nsec.FILE_GENERIC_READ | nsec.FILE_GENERIC_WRITE,
                    user
                )
                sd.SetSecurityDescriptorDacl(1, dacl, 0)
                win32security.SetFileSecurity(
                    str(path),
                    win32security.DACL_SECURITY_INFORMATION,
                    sd
                )
        except Exception:
            pass

# ════════════════════════════════════════════════════════════════════════════
#                         VAULT COMPONENTS
# ════════════════════════════════════════════════════════════════════════════

class VaultCrypto:
    """Componente de criptografia do vault."""
    
    def __init__(self, enc_key: bytes, hmac_key: bytes):
        self.engine = CryptoEngine(enc_key)
        self.hmac_key = bytearray(hmac_key)
        self._mask: Optional[bytes] = None
        self._mask_lock = threading.RLock()
        self._timer: Optional[threading.Timer] = None
        self._start_masking()
    
    def _start_masking(self):
        """Inicia mascaramento de chaves."""
        self._rotate_mask()
        self._arm_timer()
    
    def _rotate_mask(self):
        """Rotaciona máscara XOR."""
        with self._mask_lock:
            if self._mask:
                # Remove máscara antiga
                for i in range(len(self.hmac_key)):
                    self.hmac_key[i] ^= self._mask[i % len(self._mask)]
            
            # Nova máscara
            self._mask = secrets.token_bytes(32)
            
            # Aplica nova máscara
            for i in range(len(self.hmac_key)):
                self.hmac_key[i] ^= self._mask[i % len(self._mask)]
    
    def _arm_timer(self):
        """Agenda próxima rotação."""
        if self._timer:
            self._timer.cancel()
        
        self._timer = threading.Timer(0.5, self._tick)
        self._timer.daemon = True
        self._timer.start()
    
    def _tick(self):
        """Callback do timer."""
        self._rotate_mask()
        self._arm_timer()
    
    def encrypt(self, data: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        """Encripta dados."""
        compressed = StreamingCompressor.compress(data)
        return self.engine.encrypt(compressed, aad)
    
    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """Decripta dados."""
        compressed = self.engine.decrypt(nonce, ciphertext, aad)
        return StreamingCompressor.decompress(compressed)
    
    def compute_hmac(self, data: bytes) -> bytes:
        """Calcula HMAC dos dados."""
        with self._mask_lock:
            # Remove máscara temporariamente
            if self._mask:
                for i in range(len(self.hmac_key)):
                    self.hmac_key[i] ^= self._mask[i % len(self._mask)]
            
            result = hmac.new(bytes(self.hmac_key), data, hashlib.sha256).digest()
            
            # Reaplica máscara
            if self._mask:
                for i in range(len(self.hmac_key)):
                    self.hmac_key[i] ^= self._mask[i % len(self._mask)]
        
        return result
    
    def clear(self):
        """Limpa chaves da memória."""
        if self._timer:
            self._timer.cancel()
        
        self.engine.clear()
        for i in range(len(self.hmac_key)):
            self.hmac_key[i] = 0

class VaultIndex:
    """Índice de arquivos no vault."""
    
    def __init__(self):
        self.entries: Dict[str, VaultEntry] = {}
        self.lock = threading.RLock()
    
    def add(self, label: str, data: bytes) -> VaultEntry:
        """Adiciona entrada ao índice."""
        with self.lock:
            # Sanitiza label
            safe_label = SecureSerializer._sanitize_label(label)
            
            # Previne duplicatas
            if safe_label in self.entries:
                counter = 1
                while f"{safe_label}_{counter}" in self.entries:
                    counter += 1
                safe_label = f"{safe_label}_{counter}"
            
            entry = VaultEntry(
                label=safe_label,
                data=data,
                created_at=time.time(),
                size=len(data),
                checksum=hashlib.sha256(data).hexdigest()
            )
            
            self.entries[safe_label] = entry
            return entry
    
    def remove(self, label: str) -> bool:
        """Remove entrada do índice."""
        with self.lock:
            safe_label = SecureSerializer._sanitize_label(label)
            if safe_label in self.entries:
                del self.entries[safe_label]
                return True
            return False
    
    def get(self, label: str) -> Optional[VaultEntry]:
        """Obtém entrada do índice."""
        with self.lock:
            safe_label = SecureSerializer._sanitize_label(label)
            return self.entries.get(safe_label)
    
    def list_entries(self) -> List[str]:
        """Lista todas as labels."""
        with self.lock:
            return list(self.entries.keys())
    
    def get_total_size(self) -> int:
        """Calcula tamanho total."""
        with self.lock:
            return sum(entry.size for entry in self.entries.values())
    
    def clear(self):
        """Limpa índice."""
        with self.lock:
            self.entries.clear()

# ════════════════════════════════════════════════════════════════════════════
#                        MAIN VAULT MANAGER
# ════════════════════════════════════════════════════════════════════════════

class VaultManager:
    """Gerenciador principal do vault."""
    
    def __init__(
        self,
        storage: Optional[StorageBackend] = None,
        path: Optional[Path] = None
    ):
        path = path or Config.default_vault_path()
        self.storage = storage or AtomicStorageBackend(path)
        self.rate_limiter = RateLimiter(Config.LOCKOUT_WINDOW, Config.MAX_ATTEMPTS)
        self.serializer = SecureSerializer()
        self.index = VaultIndex()
        self.crypto: Optional[VaultCrypto] = None
        self.kdf_params: Optional[KDFParams] = None
        self._locked = False
    
    def create(self, master_password: SecureMemory):
        """Cria novo vault."""
        try:
            # Parâmetros KDF
            self.kdf_params = Config.get_kdf_params()
            salt = secrets.token_bytes(Config.SALT_SIZE)
            
            # Deriva chaves
            enc_key, hmac_key = derive_keys(master_password, salt, self.kdf_params)
            self.crypto = VaultCrypto(enc_key, hmac_key)
            
            # Cria header
            header = VaultHeader(
                magic=Config.MAGIC,
                version=Config.VERSION,
                salt=salt,
                nonce=b"\x00" * Config.NONCE_SIZE,  # Será gerado por encrypt
                kdf=self.kdf_params
            )
            
            # Serializa índice vazio
            serialized = self.serializer.serialize(self.index.entries)
            
            # Encripta vinculando o header cru como AAD
            nonce = self.crypto.engine.gen_nonce()
            if self.crypto.engine.backend == "chacha20" and len(nonce) == 12:
                nonce = nonce + (b"\x00" * 12)
            hdr = HEADER_STRUCT.pack(
                Config.MAGIC,
                Config.VERSION,
                salt,
                nonce,
                self.kdf_params.time_cost,
                self.kdf_params.memory_cost,
                self.kdf_params.parallelism,
            )
            ciphertext = self.crypto.engine.encrypt_with_nonce(nonce, serialized, aad=hdr)
            # MAC do header e gravação
            mac = self.crypto.compute_hmac(hdr)
            final_blob = hdr + mac + ciphertext
            self.storage.save(final_blob)
            
            log = _get_logger()
            log.info("Vault criado com sucesso")
            
        except Exception as e:
            if self.crypto:
                self.crypto.clear()
            raise CorruptVault(f"Erro ao criar vault: {e}")
    
    def open(self, master_password: SecureMemory):
        """Abre vault existente."""
        try:
            # Rate limiting
            self.rate_limiter.check("vault_open")
            
            # Carrega dados
            blob = self.storage.load()
            if not blob or len(blob) < TOTAL_HEADER:
                raise FileNotFoundError("Vault inexistente ou vazio")
            
            # Parse header temporário para obter salt
            header_raw = blob[:TOTAL_HEADER]
            _, _, salt, _, t, m, p = struct.unpack(">4sB16s24sHIB", header_raw[:HEADER_LEN])
            
            # Deriva chaves
            self.kdf_params = KDFParams(t, m, p)
            enc_key, hmac_key = derive_keys(master_password, salt, self.kdf_params)
            
            # Valida header com HMAC
            header = VaultHeader.unpack(header_raw, hmac_key)
            
            # Validações
            if header.magic != Config.MAGIC:
                raise CorruptVault("Magic inválido")
            if header.version != Config.VERSION:
                raise CorruptVault(f"Versão incompatível: {header.version}")
            
            # Inicializa crypto
            self.crypto = VaultCrypto(enc_key, hmac_key)
            
            # Decripta conteúdo
            ciphertext = blob[TOTAL_HEADER:]
            aad = header_raw[:HEADER_LEN]  # vincula header cru como AAD
            try:
                plaintext = self.crypto.decrypt(header.nonce, ciphertext, aad=aad)
            except InvalidTag:
                # Adiciona delay para evitar timing attack
                time.sleep(secrets.randbelow(100) / 1000)
                # Fallback para arquivos antigos (sem AAD)
                try:
                    plaintext = self.crypto.decrypt(header.nonce, ciphertext, aad=b"")
                    # Migra e regrava usando AAD
                    self.index.entries = self.serializer.deserialize(plaintext)
                    self._save()
                except InvalidTag:
                    self.rate_limiter.record_failure("vault_open")
                    raise WrongPassword("Senha incorreta")
            
            # Deserializa
            self.index.entries = self.serializer.deserialize(plaintext)
            
            # Sucesso
            self.rate_limiter.clear("vault_open")
            
            log = _get_logger()
            log.info(f"Vault aberto: {len(self.index.entries)} arquivos")
            
        except (WrongPassword, VaultLocked):
            raise
        except Exception as e:
            if self.crypto:
                self.crypto.clear()
            raise CorruptVault(f"Erro ao abrir vault: {e}")
    
    def add_file(self, file_path: str | Path, label: Optional[str] = None):
        """Adiciona arquivo ao vault."""
        if not self.crypto:
            raise RuntimeError("Vault não está aberto")
        
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Arquivo não encontrado: {file_path}")
        
        # Lê arquivo
        data = file_path.read_bytes()
        
        # Verifica tamanho
        new_size = self.index.get_total_size() + len(data)
        if new_size > Config.MAX_VAULT_SIZE:
            raise ValueError(
                f"Tamanho excede limite do vault ({Config.MAX_VAULT_SIZE // (2**20)} MB)"
            )
        
        # Adiciona ao índice
        label = label or file_path.name
        entry = self.index.add(label, data)
        
        # Salva
        self._save()
        
        return entry.label
    
    def export_file(self, label: str, dest_dir: str | Path) -> str:
        """Exporta arquivo do vault."""
        if not self.crypto:
            raise RuntimeError("Vault não está aberto")
        
        entry = self.index.get(label)
        if not entry:
            raise KeyError(f"Arquivo não encontrado: {label}")
        
        # Prepara destino com proteção contra path traversal
        dest_dir = Path(dest_dir).resolve()
        safe_name = Path(entry.label).name  # Remove qualquer path
        # Sanitiza nome
        safe_name = safe_name.replace("\x00", "_")
        try:
            safe_name = safe_name.encode('ascii', 'ignore').decode('ascii')
        except Exception:
            pass
        if not safe_name or safe_name in ('.', '..'):
            safe_name = f"file_{hashlib.sha256(entry.label.encode()).hexdigest()[:8]}"
        out_path = dest_dir / safe_name
        
        # Verifica se o caminho final está dentro do diretório destino
        try:
            if not out_path.resolve().is_relative_to(dest_dir):
                raise ValueError("Tentativa de path traversal detectada")
        except AttributeError:
            if not str(out_path.resolve()).startswith(str(dest_dir)):
                raise ValueError("Tentativa de path traversal detectada")
        
        # Evita sobrescrita
        if out_path.exists() and out_path.is_symlink():
            raise ValueError("Destino é um link simbólico - operação bloqueada")
        counter = 1
        while out_path.exists():
            stem = out_path.stem
            suffix = out_path.suffix
            out_path = dest_dir / f"{stem}_{counter}{suffix}"
            counter += 1
        
        # Escreve arquivo
        dest_dir.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(entry.data)
        
        return str(out_path)
    
    def delete_file(self, label: str):
        """Remove arquivo do vault."""
        if not self.crypto:
            raise RuntimeError("Vault não está aberto")
        
        if not self.index.remove(label):
            raise KeyError(f"Arquivo não encontrado: {label}")
        
        self._save()
    
    def list_files(self) -> List[str]:
        """Lista arquivos no vault."""
        if not self.crypto:
            raise RuntimeError("Vault não está aberto")
        
        return self.index.list_entries()
    
    def change_password(self, old_password: SecureMemory, new_password: SecureMemory):
        """Troca senha do vault."""
        if not self.crypto:
            raise RuntimeError("Vault não está aberto")
        
        # Valida senha antiga
        blob = self.storage.load()
        header_raw = blob[:TOTAL_HEADER]
        _, _, salt, _, _, _, _ = struct.unpack(">4sB16s24sHIB", header_raw[:HEADER_LEN])
        
        # Tenta derivar com senha antiga
        _, old_hmac = derive_keys(old_password, salt, self.kdf_params)
        
        try:
            VaultHeader.unpack(header_raw, old_hmac)
        except WrongPassword:
            # Adiciona delay para evitar timing attack
            time.sleep(secrets.randbelow(100) / 1000)
            raise WrongPassword("Senha atual incorreta")
        
        # Gera novo salt e deriva novas chaves
        new_salt = secrets.token_bytes(Config.SALT_SIZE)
        new_enc_key, new_hmac_key = derive_keys(new_password, new_salt, self.kdf_params)
        
        # Atualiza crypto
        if self.crypto:
            self.crypto.clear()
        self.crypto = VaultCrypto(new_enc_key, new_hmac_key)
        
        # Salva com novas chaves
        self._save(new_salt)
    
    def rotate_keys(self, master_password: SecureMemory):
        """Rotaciona chaves mantendo a mesma senha."""
        self.change_password(master_password, master_password)
    
    def _save(self, salt: Optional[bytes] = None):
        """Salva vault no disco."""
        if not self.crypto:
            raise RuntimeError("Vault não está aberto")
        
        # Usa salt existente ou novo
        if salt is None:
            blob = self.storage.load()
            if blob and len(blob) >= TOTAL_HEADER:
                _, _, salt, _, _, _, _ = struct.unpack(">4sB16s24sHIB", blob[:HEADER_LEN])
            else:
                salt = secrets.token_bytes(Config.SALT_SIZE)
        
        # Serializa índice
        serialized = self.serializer.serialize(self.index.entries)
        
        # Encripta vinculando o header cru como AAD
        nonce = self.crypto.engine.gen_nonce()
        if self.crypto.engine.backend == "chacha20" and len(nonce) == 12:
            nonce = nonce + (b"\x00" * 12)
        hdr = HEADER_STRUCT.pack(
            Config.MAGIC,
            Config.VERSION,
            salt,
            nonce,
            self.kdf_params.time_cost,
            self.kdf_params.memory_cost,
            self.kdf_params.parallelism,
        )
        ciphertext = self.crypto.engine.encrypt_with_nonce(nonce, serialized, aad=hdr)
        
        # Header “cru” (sem MAC)
        hdr = HEADER_STRUCT.pack(
            Config.MAGIC,
            Config.VERSION,
            salt,
            nonce,
            self.kdf_params.time_cost,
            self.kdf_params.memory_cost,
            self.kdf_params.parallelism,
        )
        # MAC com chave HMAC “desmascarada” (a própria classe cuida disso)
        mac = self.crypto.compute_hmac(hdr)

        final_blob = hdr + mac + ciphertext
        self.storage.save(final_blob)

        log = _get_logger()
        log.info(f"Vault salvo: {len(self.index.entries)} arquivos, {len(final_blob)} bytes")
    
    def close(self):
        """Fecha vault limpando memória."""
        if self.crypto:
            self.crypto.clear()
            self.crypto = None
        self.index.clear()
        self._locked = True

# ════════════════════════════════════════════════════════════════════════════
#                              HELPERS
# ════════════════════════════════════════════════════════════════════════════

def _get_logger() -> logging.Logger:
    """Obtém logger configurado."""
    logger = logging.getLogger("vault")
    
    if not logger.handlers:
        Config.LOG_PATH.parent.mkdir(exist_ok=True)
        
        handler = RotatingFileHandler(
            Config.LOG_PATH,
            maxBytes=5 * 2**20,
            backupCount=2,
            encoding="utf-8"
        )
        
        formatter = SecureFormatter(
            "%(asctime)s │ %(levelname)s │ %(message)s"
        )
        handler.setFormatter(formatter)
        
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        
        # Permissões restritivas no log
        try:
            os.chmod(Config.LOG_PATH, 0o600)
        except Exception:
            pass
    
    return logger

def open_or_init_vault(
    master_password: str | bytes,
    path: Optional[Path] = None
) -> VaultManager:
    """Helper para abrir ou criar vault."""
    path = path or Config.default_vault_path()
    vm = VaultManager(path=path)
    
    try:
        vm.open(SecureMemory(master_password))
    except FileNotFoundError:
        vm.create(SecureMemory(master_password))
    except WrongPassword:
        raise
    except CorruptVault:
        raise
    
    return vm

# ════════════════════════════════════════════════════════════════════════════
#                              GUI (Desacoplada)
# ════════════════════════════════════════════════════════════════════════════

class VaultPresenter:
    """Presenter para separar lógica da GUI."""
    
    def __init__(self, vault_manager: VaultManager):
        self.vault = vault_manager
    
    def get_files(self) -> List[str]:
        """Obtém lista de arquivos."""
        return self.vault.list_files()
    
    def export_file(self, label: str, dest_dir: str) -> str:
        """Exporta arquivo."""
        return self.vault.export_file(label, dest_dir)
    
    def delete_file(self, label: str):
        """Remove arquivo."""
        self.vault.delete_file(label)
    
    def reorder_files(self, new_order: List[str]):
        """Reordena arquivos no índice."""
        # Mantém ordem para exibição
        old_entries = self.vault.index.entries
        new_entries = {}
        
        for label in new_order:
            if label in old_entries:
                new_entries[label] = old_entries[label]
        
        # Adiciona qualquer item não listado
        for label, entry in old_entries.items():
            if label not in new_entries:
                new_entries[label] = entry
        
        self.vault.index.entries = new_entries
        self.vault._save()

class VaultDialog(QDialog):
    """Dialog Qt para gerenciar vault."""
    
    file_selected = Signal(str)
    
    def __init__(self, vault_manager: VaultManager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.presenter = VaultPresenter(vault_manager)
        self.setWindowTitle("Vault – Arquivos")
        self.resize(420, 380)
        self._build_ui()
        self._populate()
    
    def _build_ui(self):
        """Constrói interface."""
        layout = QVBoxLayout(self)
        
        # Lista
        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QListWidget.SingleSelection)
        self.list_widget.setDragEnabled(True)
        self.list_widget.setDragDropMode(QListWidget.InternalMove)
        self.list_widget.setDefaultDropAction(Qt.MoveAction)
        self.list_widget.model().rowsMoved.connect(self._on_reorder)
        self.list_widget.itemDoubleClicked.connect(self._on_double_click)
        
        layout.addWidget(QLabel("Duplo-clique para extrair:"))
        layout.addWidget(self.list_widget, 1)
        
        # Botões
        button_layout = QHBoxLayout()
        
        btn_delete = QPushButton("Remover")
        btn_delete.clicked.connect(self._on_delete)
        
        btn_export = QPushButton("Exportar para...")
        btn_export.clicked.connect(self._on_export)
        
        btn_close = QPushButton("Fechar")
        btn_close.clicked.connect(self.reject)
        
        button_layout.addWidget(btn_delete)
        button_layout.addStretch()
        button_layout.addWidget(btn_export)
        button_layout.addStretch()
        button_layout.addWidget(btn_close)
        
        layout.addLayout(button_layout)
    
    def _populate(self):
        """Preenche lista de arquivos."""
        self.list_widget.clear()
        self.list_widget.addItems(self.presenter.get_files())
    
    def _on_double_click(self, item):
        """Exporta arquivo com duplo-clique."""
        if not item:
            return
        
        label = item.text()
        
        # Para .cg2, exporta para temp silenciosamente
        if label.lower().endswith(".cg2"):
            import tempfile
            temp_dir = Path(tempfile.gettempdir())
            
            try:
                out_path = self.presenter.export_file(label, str(temp_dir))
                os.chmod(out_path, 0o600)
                self.file_selected.emit(out_path)
                self.accept()
            except Exception as e:
                QMessageBox.critical(self, "Erro", str(e))
        else:
            # Outros arquivos, pergunta destino
            dest_dir = QFileDialog.getExistingDirectory(
                self, "Salvar em...", str(Path.home())
            )
            if dest_dir:
                self._export_to(label, dest_dir)
    
    def _on_export(self):
        """Exporta arquivo selecionado."""
        item = self.list_widget.currentItem()
        if not item:
            QMessageBox.information(self, "Vault", "Selecione um arquivo primeiro.")
            return
        
        dest_dir = QFileDialog.getExistingDirectory(
            self, "Escolher pasta de destino", str(Path.home())
        )
        if dest_dir:
            self._export_to(item.text(), dest_dir)
    
    def _export_to(self, label: str, dest_dir: str):
        """Exporta arquivo para diretório."""
        try:
            out_path = self.presenter.export_file(label, dest_dir)
            QMessageBox.information(self, "Exportado", f"Arquivo salvo em:\n{out_path}")
            self.file_selected.emit(out_path)
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Erro", str(e))
    
    def _on_delete(self):
        """Remove arquivo selecionado."""
        item = self.list_widget.currentItem()
        if not item:
            return
        
        label = item.text()
        reply = QMessageBox.question(
            self, "Confirmar", f"Remover {label} do vault?"
        )
        
        if reply == QMessageBox.Yes:
            try:
                self.presenter.delete_file(label)
                self._populate()
            except Exception as e:
                QMessageBox.critical(self, "Erro", str(e))
    
    def _on_reorder(self):
        """Salva nova ordem dos arquivos."""
        new_order = [
            self.list_widget.item(i).text()
            for i in range(self.list_widget.count())
        ]
        self.presenter.reorder_files(new_order)

# ════════════════════════════════════════════════════════════════════════════
#                              MAIN
# ════════════════════════════════════════════════════════════════════════════

def main():
    """CLI para testes."""
    import argparse
    import getpass
    
    ProcessProtection.apply()
    
    parser = argparse.ArgumentParser(description="Vault CLI")
    parser.add_argument("vault_file", type=Path, help="Arquivo do vault")
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Comandos
    subparsers.add_parser("init", help="Criar novo vault")
    
    add_parser = subparsers.add_parser("add", help="Adicionar arquivo")
    add_parser.add_argument("file", type=Path, help="Arquivo para adicionar")
    add_parser.add_argument("--label", help="Label customizada")
    
    subparsers.add_parser("list", help="Listar arquivos")
    
    export_parser = subparsers.add_parser("export", help="Exportar arquivo")
    export_parser.add_argument("label", help="Label do arquivo")
    export_parser.add_argument("dest", type=Path, help="Diretório destino")
    
    delete_parser = subparsers.add_parser("delete", help="Remover arquivo")
    delete_parser.add_argument("label", help="Label do arquivo")
    
    subparsers.add_parser("passwd", help="Trocar senha")
    
    args = parser.parse_args()
    
    # Executa comando
    vm = VaultManager(path=args.vault_file)
    
    if args.command == "init":
        password = getpass.getpass("Nova senha mestre: ")
        vm.create(SecureMemory(password))
        print("Vault criado com sucesso.")
    
    else:
        password = getpass.getpass("Senha mestre: ")
        vm.open(SecureMemory(password))
        
        if args.command == "add":
            label = vm.add_file(args.file, args.label)
            print(f"Arquivo adicionado como: {label}")
        
        elif args.command == "list":
            files = vm.list_files()
            if files:
                print("Arquivos no vault:")
                for f in files:
                    print(f"  - {f}")
            else:
                print("Vault vazio.")
        
        elif args.command == "export":
            out_path = vm.export_file(args.label, args.dest)
            print(f"Exportado para: {out_path}")
        
        elif args.command == "delete":
            vm.delete_file(args.label)
            print(f"Arquivo {args.label} removido.")
        
        elif args.command == "passwd":
            new_password = getpass.getpass("Nova senha mestre: ")
            confirm = getpass.getpass("Confirme a nova senha: ")
            
            if new_password != confirm:
                print("Senhas não coincidem!")
                sys.exit(1)
            
            vm.change_password(SecureMemory(password), SecureMemory(new_password))
            print("Senha alterada com sucesso.")

if __name__ == "__main__":
    main()
