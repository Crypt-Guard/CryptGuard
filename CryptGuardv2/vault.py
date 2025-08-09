#!/usr/bin/env python3
"""vault.py – Vault 3.x adaptado para integração com CryptGuard v2.6.3

✔ Mudanças principais para funcionar no fluxo GUI do CryptGuard:
    • API de alto nível (`open_or_init_vault`, `VaultManager.add_file`, `VaultManager.export_file`,
      `VaultManager.list_files`) para guardar/recuperar arquivos já **criptografados**.
    • Limite opcional de tamanho (10 MB por padrão) permanece.
    • Janela Qt (`VaultDialog`) para navegação visual do cofre – abre como um diálogo modal,
      retorna o caminho do arquivo exportado via sinal `file_selected(str)`.

"""

from __future__ import annotations
import argparse, base64, ctypes, getpass, hmac, hashlib
import multiprocessing, os, platform, secrets, stat, struct, sys, tempfile, threading, time, warnings
from pathlib import Path
from typing import Dict, Tuple, Union, Optional, List, Callable, TypeVar
import logging
from logging.handlers import RotatingFileHandler  # <-- Importar explicitamente
import json
import gzip, io, pickle

# ─── Dependências mínimas ───────────────────────────────────────────────────
REQ = ("cryptography", "argon2", "psutil", "PySide6")
missing = [pkg for pkg in REQ if not (pkg in sys.modules or __import__(pkg, fromlist=[""]))]
if missing:
    print("Dependências faltando:", ", ".join(missing))
    print("→  pip install -U " + " ".join(missing))
    sys.exit(1)

import psutil                             # noqa: E402
import argon2.low_level as _argon2        # noqa: E402
from argon2.low_level import Type as _ArgonType  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
try:
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
except ImportError:
    XChaCha20Poly1305 = None  # ← sem suporte oficial

# PyCryptodome (fallback XChaCha)
try:
    from Crypto.Cipher import ChaCha20_Poly1305 as PyChaCha
except ImportError:
    PyChaCha = None

from cryptography.exceptions import InvalidTag  # <-- Add this import

# libsodium (opcional – caminho rápido) --------------------------------------
try:
    import pysodium as sodium             # noqa: E402
except Exception:
    sodium = None

# Qt (GUI) -------------------------------------------------------------------
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialog, QListWidget, QVBoxLayout, QListWidgetItem, QFileDialog,
    QMessageBox, QPushButton, QHBoxLayout, QLabel, QWidget
)

if platform.system() == "Windows":
    try:
        import win32security, ntsecuritycon as nsec, win32api  # type: ignore # noqa: E402,E501
    except ImportError:
        win32security = nsec = win32api = None  # type: ignore

# ---------------------------------------------------------------------------+
# Hardening de processo (anti-debug, sem core-dump, mlock)                   +
# ---------------------------------------------------------------------------+

def _harden_process_once() -> None:
    """Aplica hardening semelhante ao KeyGuard (executa só 1 vez)."""
    if getattr(_harden_process_once, "_done", False):
        return

    # a) desabilita core-dumps
    if hasattr(os, "setrlimit"):
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            pass

    # b) alerta se debugger está anexado
    if sys.gettrace() is not None:
        warnings.warn(SecurityWarning("Debugger detectado — execução pode estar comprometida", "debug", "high"))

    # c) trava páginas de memória (best-effort)
    try:
        if platform.system() == "Linux":
            libc = ctypes.CDLL("libc.so.6")
            libc.mlockall(1)           # MCL_CURRENT
        elif platform.system() == "Windows" and hasattr(ctypes, "windll"):
            ctypes.windll.kernel32.SetProcessWorkingSetSize(-1, -1, -1)
    except Exception:
        pass

    _harden_process_once._done = True

# Aplica hardening assim que o módulo é importado
_harden_process_once()

# ### B  --  Compressão/decompressão para grandes cofres
CHUNK = 64 * 1024

def _compress(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as z:
        for i in range(0, len(data), CHUNK):
            z.write(data[i : i + CHUNK])
    return buf.getvalue()

def _decompress(data: bytes) -> bytes:
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as z:
        while True:
            part = z.read(CHUNK)
            if not part:
                break
            out.write(part)
    return out.getvalue()

# ═════════════════════════ Configurações ════════════════════════════════════
class Config:
    MAGIC: bytes = b"VLT3"          # 4 bytes para identificação
    VERSION: int = 3
    SALT_SIZE: int = 16             # Revertido para 16 bytes para compatibilidade com o formato do cabeçalho
    NONCE_SIZE: int = 24          # header V3 grava sempre 24 B
    KEY_SIZE: int = 32
    HMAC_SIZE: int = 32
    # Aumenta o limite do cofre para 128 MB (>= 100 MB como solicitado)
    MAX_VAULT_SIZE: int = 128 * 2**20  # 128 MB
    MIN_MASTER_PW_LEN: int = 12
    ARGON_TIME = 6                  # parâmetros mínimos caso calibração falhe
    ARGON_MEM = 2 ** 20             # 1 GiB em KiB
    ARGON_PARALLEL = min(8, multiprocessing.cpu_count() or 2)
    MAX_ATTEMPTS = 5
    REQUIRE_2FA = False
    INI_PATH = Path.home() / ".cryptguard" / "vault.ini"  # único ponto‑fonte
    @classmethod
    def get_kdf_params(cls):
        """
        Consulta (ou cria) ~/.cryptguard/vault.ini e devolve sempre
        **os mesmos** parâmetros Argon2id entre execuções.
        """
        legacy = Path.home() / ".cryptguard" / "config.ini"
        if legacy.exists() and not cls.INI_PATH.exists():
            legacy.replace(cls.INI_PATH)          # move antigo → novo nome

        import configparser, psutil, secrets, time, argon2.low_level as low
        if cls.INI_PATH.exists():
            cp = configparser.ConfigParser(); cp.read(cls.INI_PATH)
            return {k: cp.getint("kdf", k) for k in ("time_cost", "memory_cost", "parallelism")}

        # 1.ª vez – calibra
        salt = secrets.token_bytes(16); pw = b"benchmark"
        mem  = max(2**19, cls.ARGON_MEM); t = max(4, cls.ARGON_TIME)
        par  = cls.ARGON_PARALLEL; vmax = psutil.virtual_memory().total * 0.75
        target_ms = 1000  # Definir target_ms como em dynamic_kdf
        while True:
            t0 = time.perf_counter()
            low.hash_secret_raw(pw, salt, t, mem, par, 32, low.Type.ID)
            if (time.perf_counter()-t0)*1000 >= target_ms or mem*2*1024 > vmax:
                break
            mem <<= 1

        cp = configparser.ConfigParser()
        cp["kdf"] = {"time_cost": t, "memory_cost": mem, "parallelism": par}
        cls.INI_PATH.parent.mkdir(exist_ok=True)
        with open(cls.INI_PATH, "w", encoding="utf-8") as f:
            cp.write(f)
        os.chmod(cls.INI_PATH, 0o600)
        return {"time_cost": t, "memory_cost": mem, "parallelism": par}

    @classmethod
    def default_path(cls) -> Path:
        """Retorna o caminho‑padrão do arquivo de cofre."""
        if platform.system() == "Windows":
            appdata = os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
            p = Path(appdata) / "CryptGuard" / "vault3.dat"
        else:
            p = Path.home() / ".cryptguard" / "vault3.dat"
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    @classmethod
    def dynamic_kdf(cls, target_ms: int = 1000) -> Dict[str, int]:
        """Calibra Argon2 para gastar ~target_ms ms em hardware local."""
        salt = secrets.token_bytes(16)
        pw = b"benchmark"
        mem_cost = max(2**19, cls.ARGON_MEM)
        time_cost = max(4, cls.ARGON_TIME)
        parallel = cls.ARGON_PARALLEL
        vmax = psutil.virtual_memory().total * 0.75
        while True:
            if mem_cost * 1024 > vmax:
                break
            t0 = time.perf_counter()
            _argon2.hash_secret_raw(pw, salt, time_cost, mem_cost, parallel, 32, _ArgonType.ID)
            dur = (time.perf_counter() - t0) * 1000
            if dur >= target_ms or mem_cost * 2 * 1024 > vmax:
                break
            mem_cost <<= 1
        return dict(time_cost=time_cost, memory_cost=mem_cost, parallelism=parallel)

KDF_PARAMS = Config.get_kdf_params()

# ═════════════════════════ Logging seguro ═══════════════════════════════════

def _setup_logger() -> logging.Logger:
    path = Path.home() / ".cryptguard" / "vault.log"
    path.parent.mkdir(exist_ok=True, parents=True)
    handler = RotatingFileHandler(path, maxBytes=5 * 2**20, backupCount=2, encoding="utf-8")  # <-- Usar diretamente
    fmt = logging.Formatter("%(asctime)s │ %(levelname)s │ %(message)s")
    handler.setFormatter(fmt)
    lg = logging.getLogger("vault")
    lg.setLevel(logging.INFO)
    lg.addHandler(handler)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return lg

log = _setup_logger()

# ═════════════════════════ Classe de aviso ══════════════════════════════════
class SecurityWarning(UserWarning):
    def __init__(self, msg: str, category: str, sev: str = "medium") -> None:
        super().__init__(msg)
        txt = f"[{sev.upper()}] {category}: {msg}"
        getattr(log, {"critical": "critical", "high": "error", "medium": "warning"}.get(sev, "info"))(txt)

# ═════════════════════════ Process security (simpl.) ═══════════════════════=
class ProcessProtection:
    """Mesmo esquema do KeyGuard – reduzido."""
    _applied = False

    @classmethod
    def apply(cls):
        if cls._applied:
            return
        cls._applied = True
        # Bloqueia core‑dumps em POSIX
        if hasattr(os, "setrlimit"):
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # DEP / ASLR extra em Windows
        if platform.system() == "Windows":
            try:
                kernel32 = ctypes.WinDLL("kernel32")
                kernel32.SetProcessDEPPolicy(1)
            except Exception:
                pass
        # watchdog anti‑debugging
        threading.Thread(target=cls._watchdog, daemon=True).start()

    @staticmethod
    def _watchdog():
        while True:
            t0 = time.perf_counter(); time.sleep(0.1)
            if time.perf_counter() - t0 > 1.0:
                warnings.warn(SecurityWarning("Timing‑glitch – possível debugger", "debug", "high"))

ProcessProtection.apply()

# ═════════════════════════ SecureMemory helper ══════════════════════════════
class SecureMemory:
    def __init__(self, data: Union[str, bytes, bytearray, object]):
        # Aceita objetos como SecureBytes, que têm .bytes()
        if not isinstance(data, (str, bytes, bytearray)):
            if hasattr(data, "bytes"):
                data = data.bytes()
            elif hasattr(data, "__bytes__"):
                data = bytes(data)
        if isinstance(data, str):
            data = data.encode()
        self._buf = bytearray(data)
        self._lock_pages()

    def _lock_pages(self):
        size = len(self._buf)
        ok = False
        try:
            if platform.system() == "Windows" and hasattr(ctypes, "windll"):
                # ✅ pega o endereço e passa como void*
                addr = ctypes.addressof(ctypes.c_char.from_buffer(self._buf))
                ok = bool(ctypes.windll.kernel32.VirtualLock(
                    ctypes.c_void_p(addr), ctypes.c_size_t(size)
                ))
            else:
                # Linux/BSD/macOS
                libc = None
                try:
                    libc = ctypes.CDLL("libc.so.6")
                except Exception:
                    try:
                        libc = ctypes.CDLL("libSystem.B.dylib")  # macOS
                    except Exception:
                        libc = None
                if libc is not None:
                    ok = (libc.mlock(
                        ctypes.addressof(ctypes.c_char.from_buffer(self._buf)),
                        ctypes.c_size_t(size)
                    ) == 0)
        except Exception:
            ok = False

        if not ok:
            warnings.warn("mlock/VirtualLock falhou – páginas não protegidas")

    def bytes(self) -> bytes:  # raw
        return bytes(self._buf)

    def clear(self):
        for p in (b"\xff", b"\x00", b"\x55", b"\xaa"):
            self._buf[:] = p * len(self._buf)
        if "sodium" in globals() and sodium:
            sodium.memzero(self._buf)

    def __del__(self):
        self.clear()

# ═════════════════════════ Derivação de chaves ══════════════════════════════

def _argon2id(pw: bytes, salt: bytes, params: Optional[Dict[str, int]] = None) -> bytes:
    p = params or KDF_PARAMS
    return _argon2.hash_secret_raw(pw, salt, p["time_cost"], p["memory_cost"], p["parallelism"], 64, _ArgonType.ID)


def derive_keys(password: SecureMemory, salt: bytes, params: Optional[Dict[str, int]] = None) -> Tuple[bytes, bytes]:
    master = _argon2id(password.bytes(), salt, params)
    outer = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b"Vault split v3").derive(master)
    return outer[:32], outer[32:]  # enc_key, hmac_key

# ═════════════════════════ Engine AEAD ═════════════════════════════════════
class CryptoEngine:
    """
    Backend único que negocia:
      • cryptography.XChaCha20Poly1305         (24 B)
      • PyCryptodome ChaCha20_Poly1305 (24 B)  (modo XChaCha)
      • cryptography.ChaCha20Poly1305  (12 B)  (modo IETF)
      • libsodium (12 B) – mantido, mas agora com padding correto
    """
    def __init__(self, enc_key: bytes, force_chacha: bool = False):
        self.key = bytearray(enc_key)
        if force_chacha:
            self._backend = "crypto_ietf"
            self._nonce_len = 12
        elif XChaCha20Poly1305:
            self._backend = "crypto_x"
            self._nonce_len = 24
        elif PyChaCha:
            self._backend = "pycrypto_x"
            self._nonce_len = 24
        elif sodium:
            self._backend = "sodium"
            self._nonce_len = sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES
        else:
            self._backend = "crypto_ietf"
            self._nonce_len = 12

    def enc(self, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        if self._backend == "sodium":
            npub_len = self._nonce_len             # 12
            npub = sodium.randombytes(npub_len)
            ct   = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
                       plaintext, aad, npub, self.key)
            full_nonce = npub + secrets.token_bytes(24 - npub_len)  # padding
            return full_nonce, ct

        if self._backend == "crypto_x":
            full_nonce = secrets.token_bytes(24)
            ct = XChaCha20Poly1305(bytes(self.key)).encrypt(full_nonce, plaintext, aad)
            return full_nonce, ct
        elif self._backend == "pycrypto_x":
            full_nonce = secrets.token_bytes(24)
            cipher = PyChaCha.new(key=bytes(self.key), nonce=full_nonce)
            cipher.update(aad)
            ct = cipher.encrypt(plaintext) + cipher.digest()
            return full_nonce, ct
        else:  # crypto_ietf
            full_nonce = secrets.token_bytes(24)
            ct = ChaCha20Poly1305(bytes(self.key)).encrypt(full_nonce[:12], plaintext, aad)
            return full_nonce, ct

    def dec(self, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        if self._backend == "sodium":
            npub_len = self._nonce_len
            try:
                return sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
                           ciphertext, aad, nonce[:npub_len], self.key)
            except RuntimeError:
                raise InvalidTag("Tag mismatch") from None

        if self._backend == "crypto_x":
            return XChaCha20Poly1305(bytes(self.key)).decrypt(nonce, ciphertext, aad)
        elif self._backend == "pycrypto_x":
            cipher = PyChaCha.new(key=bytes(self.key), nonce=nonce)
            cipher.update(aad)
            ct, tag = ciphertext[:-16], ciphertext[-16:]
            try:
                return cipher.decrypt_and_verify(ct, tag)
            except ValueError:  # PyCryptodome → tag inválida
                raise InvalidTag("Tag mismatch") from None
        else:  # crypto_ietf
            return ChaCha20Poly1305(bytes(self.key)).decrypt(nonce[:12], ciphertext, aad)

    def clear(self):
        for i in range(len(self.key)):
            self.key[i] = 0

    def __del__(self):
        self.clear()

# ═════════════════════════ Header helpers ══════════════════════════════════

def _header_pack(salt: bytes, nonce: bytes, kdf: Dict[str, int], hmac_key: bytes) -> bytes:
    hdr = struct.pack(
        VaultManager.HEADER_FMT, Config.MAGIC, Config.VERSION, salt, nonce,
        kdf["time_cost"], kdf["memory_cost"], kdf["parallelism"]
    )
    mac = hmac.new(hmac_key, hdr, hashlib.sha256).digest()
    return hdr + mac


def _header_unpack(blob: bytes, hmac_key: bytes) -> Tuple[bytes, bytes, Dict[str,int]]:
    if len(blob) < VaultManager.HEADER_LEN:
        raise CorruptVault("Header too small")
    hdr, mac = blob[: VaultManager.HEADER_LEN - 32], blob[-32:]
    if not hmac.compare_digest(mac, hmac.new(hmac_key, hdr, hashlib.sha256).digest()):
        raise WrongPassword("Senha incorreta")
    magic, ver, salt, nonce, t, m, p = struct.unpack(VaultManager.HEADER_FMT, hdr)
    if magic != Config.MAGIC or ver != Config.VERSION:
        raise CorruptVault("Formato ou versão incompatível")
    return salt, nonce, {"time_cost": t, "memory_cost": m, "parallelism": p}

# ═════════════════════════ Backend de storage (atomic/WAL) ═════════════════
class StorageBackend:
    def __init__(self, path: Path):
        self.path = path
        self.wal = path.with_suffix(".wal")
        self.bak = path.with_suffix(".bak")
        self.bak1 = path.with_suffix(".bak1")
        self.bak2 = path.with_suffix(".bak2")

    def _atomic_write(self, data: bytes):
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent))
        with os.fdopen(fd, "wb") as fp:
            fp.write(data); fp.flush(); os.fsync(fp.fileno())
        
        # Rotacionamento de backups: .bak2 <- .bak1 <- .bak <- arquivo atual
        if self.bak.exists():
            if self.bak1.exists():
                if self.bak2.exists():
                    self.bak2.unlink()
                self.bak1.rename(self.bak2)
            self.bak.rename(self.bak1)
        
        # Se o arquivo existir, mova-o para .bak
        if self.path.exists():
            self.path.rename(self.bak)
        
        # Substitui o arquivo pelo novo
        os.replace(tmp, self.path)
        try:
            os.sync()
        except AttributeError:
            pass  # Alguns sistemas não possuem os.sync()

    def _retry_op(self, func, max_tries=3, delay=1.0):
        for attempt in range(5):
            try:
                return func()
            except (OSError, IOError) as e:
                if attempt == 4:
                    raise CorruptVault(f"Falha após 5 tentativas: {e} – possível conflito de sync") from e
                time.sleep(2.0)

    def save(self, data: bytes):
        def do_save():
            with open(self.wal, "wb") as w:
                w.write(data); w.flush(); os.fsync(w.fileno())
            self._atomic_write(data)
            self.wal.unlink(missing_ok=True)
            _perm_restrict(self.path)
            if self.bak.exists():
                _perm_restrict(self.bak)
            if self.bak1.exists():
                _perm_restrict(self.bak1)
            if self.bak2.exists():
                _perm_restrict(self.bak2)
        self._retry_op(do_save)

    def load(self) -> bytes:
        def do_load():
            if self.wal.exists():
                warnings.warn(SecurityWarning("WAL encontrado – recovery automático", "file", "high"))
                data = self.wal.read_bytes()
                self._atomic_write(data)
                self.wal.unlink(missing_ok=True)
                return data
            data = self.path.read_bytes() if self.path.exists() else b""
            if self.path.exists() and len(data) == 0:
                raise OSError("Arquivo zerado – possível corrupção")
            return data
        return self._retry_op(do_load)


def _perm_restrict(p: Path):
    try:
        if platform.system() != "Windows":
            p.chmod(stat.S_IRUSR | stat.S_IWUSR)
        elif win32security:
            sd = win32security.GetFileSecurity(str(p), win32security.DACL_SECURITY_INFORMATION)
            dacl = win32security.ACL(); user, _, _ = win32security.LookupAccountName("", win32api.GetUserName())
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, nsec.FILE_GENERIC_READ | nsec.FILE_GENERIC_WRITE, user)
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(str(p), win32security.DACL_SECURITY_INFORMATION, sd)
    except Exception:
        pass

# ═════════════════════════ Rate limiter (bruteforce) ═══════════════════════
class RateLimiter:
    def __init__(self, window: int = 300, threshold: int = 5):
        self.cfg_file = Config.INI_PATH.with_name("rate.ini")
        self.window, self.threshold = window, threshold
        self._load()

    def _load(self):
        self.fail_ts = []
        if self.cfg_file.exists():
            with self.cfg_file.open() as f:
                self.fail_ts = [float(x) for x in f.read().split(",") if x]

    def _persist(self):
        with self.cfg_file.open("w") as f:
            f.write(",".join(map(str, self.fail_ts)))

    def check(self):
        now = time.time()
        self.fail_ts = [t for t in self.fail_ts if now - t < self.window]
        if len(self.fail_ts) >= self.threshold:
            raise RuntimeError(f"Rate‑limited – aguarde {int(self.window - (now - self.fail_ts[-self.threshold]))} s")

    def fail(self):
        now = time.time()
        self.fail_ts = [t for t in self.fail_ts if now - t < self.window]
        self.fail_ts.append(now)
        self._persist()

    def success(self):
        self.fail_ts = []
        self._persist()

# ═════════════════════════ VaultManager (API pública) ═══════════════════════

# Decorator para timed exposure de chaves
T = TypeVar('T')
def _exposed(func: Callable[..., T]) -> Callable[..., T]:
    def wrapper(self: 'VaultManager', *args, **kwargs) -> T:
        with self._mask_lock:
            if getattr(self, '_mask', None):
                for i in range(len(self.enc_key)):
                    self.enc_key[i] ^= self._mask[i]
                    self.hmac_key[i] ^= self._mask[i]
            try:
                return func(self, *args, **kwargs)
            finally:
                if getattr(self, '_mask', None):
                    for i in range(len(self.enc_key)):
                        self.enc_key[i] ^= self._mask[i]
                        self.hmac_key[i] ^= self._mask[i]
                    self._arm_timer()
    return wrapper

class VaultManager:
    """Gerencia um cofre V3 (arquivo single‑blob)."""
    # MAGIC (4s) | ver (B) | salt (32s) | nonce (24s) | time_cost (H) | memory_cost (I) | parallelism (B)
    HEADER_FMT = ">4sB16s24sH I B"  # MAGIC, ver, salt, nonce, time_cost, memory_cost, parallelism
    HEADER_LEN = struct.calcsize(HEADER_FMT) + 32   # +HMAC-SHA256
    _KEY_TTL = 0.5  # chave em claro por no máximo 500 ms

    def __init__(self, storage: StorageBackend, backups: bool = True):
        self.store = storage
        self.rl = RateLimiter()
        self.db: Dict[str, str] = {}       # label → base64(data)
        self.enc: Optional[CryptoEngine] = None
        self.enc_key: bytearray = bytearray()
        self.hmac_key: bytearray = bytearray()
        self._mask: Optional[bytes] = None
        self._timer: Optional[threading.Timer] = None
        self._mask_lock = threading.RLock()
        self.backups = backups
        self.kdf_params = None  # Armazena os parâmetros KDF específicos deste vault

    def _set_keys(self, enc: bytes, mac: bytes) -> None:
        """Configura chaves com proteção de obfuscação e exposição temporária."""
        # Converte para bytearray
        self.enc_key = bytearray(enc)
        self.hmac_key = bytearray(mac)
        # Aplica primeira máscara e inicia temporizador
        self._rotate_mask()
        self._arm_timer()

    def _rotate_mask(self) -> None:
        """Rotaciona a máscara XOR para obfuscação das chaves em memória."""
        with self._mask_lock:
            if self._mask:
                for i in range(len(self.enc_key)):
                    self.enc_key[i] ^= self._mask[i]
                    self.hmac_key[i] ^= self._mask[i]
            self._mask = secrets.token_bytes(len(self.enc_key))
            for i in range(len(self.enc_key)):
                self.enc_key[i] ^= self._mask[i]
                self.hmac_key[i] ^= self._mask[i]

    def _arm_timer(self) -> None:
        """Configura temporizador para rotação automática da máscara."""
        def _tick():
            self._rotate_mask()
            self._arm_timer()
        if self._timer:
            self._timer.cancel()
        self._timer = threading.Timer(self._KEY_TTL, _tick)
        self._timer.daemon = True
        self._timer.start()

    # ── criação / abertura ────────────────────────────────────────────────
    def create(self, master: SecureMemory):
        try:
            # 1️⃣ deriva chaves
            salt = secrets.token_bytes(Config.SALT_SIZE)
            self.kdf_params = KDF_PARAMS.copy()
            enc_key, mac_key = derive_keys(master, salt, self.kdf_params)
            
            # 2️⃣ gera criptograma antes de ofuscar chaves
            engine = CryptoEngine(enc_key)
            nonce, ct = engine.enc(_compress(pickle.dumps({})))
            
            # 3️⃣ assina cabeçalho com **chave limpa**
            hdr = _header_pack(salt, nonce, self.kdf_params, mac_key)
            self.store.save(hdr + ct)
            
            # 4️⃣ só agora guarda engine e aplica máscara
            self.enc = engine
            self._set_keys(enc_key, mac_key)
            log.info("Vault criado com sucesso")
        except Exception as e:
            log.error(f"Falha na criação do Vault: {e}")
            raise CorruptVault(f"Erro ao criar Vault: {e} – verifique permissões ou sync")
    
    def open(self, master_password: Union[str, bytes, 'SecureMemory'], totp_code: Optional[str] = None, totp_secret: Optional[str] = None):
        try:
            self.rl.check()
            blob = self.store.load()
            if not blob or len(blob) == 0:
                raise FileNotFoundError("Vault inexistente ou vazio. Use create().")
            hdr_raw = blob[:VaultManager.HEADER_LEN]
            body    = blob[VaultManager.HEADER_LEN:]
            magic, ver, salt, nonce, t, m, p = struct.unpack(
                VaultManager.HEADER_FMT, hdr_raw[:-32]
            )
            if not isinstance(master_password, SecureMemory):
                master_password = SecureMemory(master_password)
                
            # Use the parameters from the header for key derivation
            self.kdf_params = {"time_cost": t, "memory_cost": m, "parallelism": p}
            enc_key, mac_key = derive_keys(master_password, salt, self.kdf_params)
            
            # Verify HMAC before key masking
            expected_mac = hmac.new(mac_key, hdr_raw[:-32], hashlib.sha256).digest()
            if not hmac.compare_digest(expected_mac, hdr_raw[-32:]):
                self.rl.fail(); raise WrongPassword("Senha incorreta")
            
            # engine uses the raw key before masking
            self.enc = CryptoEngine(enc_key)
            # Only after engine is created, we set and mask keys
            self._set_keys(enc_key, mac_key)
            
            # Warning but don't block access if parameters differ from current global ones
            if self.kdf_params != KDF_PARAMS:
                warnings.warn(
                    SecurityWarning(
                        "Parâmetros Argon2id diferentes dos actuais – a abrir em modo retro-compat.",
                        "kdf", "medium"
                    )
                )
                
            self.rl.success()
            try:
                # ① XChaCha se disponível
                plain = self.enc.dec(nonce, body)
            except InvalidTag:
                # ② fallback para ChaCha-IETF - use raw key
                self.enc = CryptoEngine(enc_key, force_chacha=True)
                try:
                    plain = self.enc.dec(nonce, body)
                except InvalidTag:
                    self.rl.fail()
                    raise WrongPassword("Senha incorreta")

            try:
                self.db = pickle.loads(_decompress(plain))
            except (pickle.UnpicklingError,
                    gzip.BadGzipFile,
                    EOFError,
                    OSError) as err:
                # Decriptou com chave errada → lixo → falha de descompressão
                self.rl.fail()
                raise WrongPassword("Senha incorreta") from err
            log.info(f"Vault aberto: {len(self.db)} arquivos")
        except InvalidTag:
            self.rl.fail()
            raise WrongPassword("Senha incorreta")
        except Exception as e:
            log.error(f"Falha ao abrir Vault: {e}")
            raise CorruptVault(f"Erro ao abrir Vault: {e} – possível corrupção por sync")

    def list_files(self) -> List[str]:
        return list(self.db.keys())

    def add_file(self, file_path: str, label: Optional[str] = None):
        """Armazena **o binário do arquivo** (já criptografado pelo CryptGuard) dentro do cofre."""
        data = Path(file_path).read_bytes()
        label = label or Path(file_path).name
        new_db = self.db.copy(); new_db[label] = base64.b64encode(data).decode()
        size_est = len(json.dumps(new_db).encode())
        if size_est > Config.MAX_VAULT_SIZE:
            raise ValueError(
                f"Tamanho excede o limite do cofre ({Config.MAX_VAULT_SIZE // (2**20)} MB)."
            )
        self.db = new_db; self._save()

    def export_file(self, label: str, dest_dir: str | Path) -> str:
        """Extrai o arquivo `label` para `dest_dir` e retorna o caminho salvo."""
        if label not in self.db:
            raise KeyError("Arquivo não encontrado no cofre")
        data = base64.b64decode(self.db[label])
        dest_dir = Path(dest_dir); dest_dir.mkdir(parents=True, exist_ok=True)
        out = dest_dir / label
        # evita overwrite
        counter = 1
        while out.exists():
            out = dest_dir / f"{out.stem}({counter}){out.suffix}"
            counter += 1
        out.write_bytes(data)
        return str(out)

    def delete(self, label: str):
        self.db.pop(label, None); self._save()

    @_exposed
    def change_password(self, old_master: SecureMemory, new_master: SecureMemory):
        """Troca de senha com verificação explícita da senha atual."""
        # 1) Ler header e extrair salt/parâmetros atuais
        hdr_raw = self.store.load()[:VaultManager.HEADER_LEN]
        if not hdr_raw:
            raise CorruptVault("Vault inexistente")
        _, _, old_salt, _, t, m, p = struct.unpack(self.HEADER_FMT, hdr_raw[:-32])
        kdf = {"time_cost": t, "memory_cost": m, "parallelism": p}

        # 2) Verificar HMAC com a senha antiga
        _, old_mac = derive_keys(old_master, old_salt, kdf)
        expected_mac = hmac.new(old_mac, hdr_raw[:-32], hashlib.sha256).digest()
        if not hmac.compare_digest(expected_mac, hdr_raw[-32:]):
            raise WrongPassword("Senha incorreta")

        # 3) Gerar chaves com novo salt e salvar
        new_salt = secrets.token_bytes(Config.SALT_SIZE)
        new_enc, new_mac = derive_keys(new_master, new_salt, kdf)
        self.enc = CryptoEngine(new_enc)
        self._set_keys(new_enc, new_mac)
        self._save(new_salt)

    @_exposed
    def rotate_keys(self, master: SecureMemory):
        """Mantém compatibilidade: troca a senha SEM exigir a senha antiga."""
        new_salt = secrets.token_bytes(Config.SALT_SIZE)
        enc_key, mac_key = derive_keys(master, new_salt, self.kdf_params)
        self.enc = CryptoEngine(enc_key)
        self._set_keys(enc_key, mac_key)
        self._save(new_salt)

    @_exposed
    def _save(self, salt: Optional[bytes] = None):
        """
        Grava DB no disco reutilizando SEMPRE o mesmo salt do cabeçalho
        existente, garantindo que `hmac_key` continue válido.
        """
        # O decorator _exposed garante que as chaves estão temporariamente expostas
        old_hdr = self.store.load()[:5 + Config.SALT_SIZE]  # MAGIC|VER|salt
        # Se um salt novo foi fornecido (troca de senha), HONRAR esse salt.
        if salt is None:
            salt = old_hdr[5:] if old_hdr else secrets.token_bytes(Config.SALT_SIZE)
        nonce, ct = self.enc.enc(_compress(pickle.dumps(self.db)))
        hdr = _header_pack(salt, nonce, self.kdf_params, bytes(self.hmac_key))
        blob = hdr + ct
        self.store.save(blob)
        total_size = len(blob)
        log.info(f"Vault salvo: {total_size / 1024:.1f} KB – arquivos: {len(self.db)}")
        # NÃO limpe a chave aqui!  Isso invalida self.enc para o
        # próximo _save() durante a mesma sessão e corrompe o Vault.
        # A chave será zerada ao fechar a aplicação ou em rotate_keys().

# ═════════════════════════ Helper de uso simples ═══════════════════════════

def open_or_init_vault(master_password: str | bytes, path: Optional[Path | str] = None) -> VaultManager:
    """Abre o cofre (ou cria se não existir) e retorna um `VaultManager`."""
    path = Path(path) if path else Config.default_path()
    sb = StorageBackend(path)
    vm = VaultManager(sb)
    try:
        vm.open(SecureMemory(master_password))
    except FileNotFoundError:
        vm.create(SecureMemory(master_password))
    except WrongPassword as e:
        # Senha incorreta (HMAC falhou) – propagamos para interface tratar
        raise
    except CorruptVault as e:
        # Arquivo corrompido ou vazio – também propagamos (UI decide recriar)
        raise
    return vm

# ═════════════════════════ GUI: VaultDialog ════════════════════════════════
class VaultDialog(QDialog):
    """Janela Qt para listar e extrair arquivos do cofre."""
    file_selected = Signal(str)  # caminho exportado

    def __init__(self, vm: VaultManager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setWindowTitle("Vault – Arquivos")
        self.resize(420, 380)
        self.vm = vm
        self._build_ui()
        self._populate()

    # ── UI -----------------------------------------------------------------
    def _build_ui(self):
        v = QVBoxLayout(self)
        self.list = QListWidget()
        # ① seleção única e D‑n‑D interno
        self.list.setSelectionMode(QListWidget.SingleSelection)
        self.list.setDragEnabled(True)
        self.list.setDragDropMode(QListWidget.InternalMove)
        self.list.setDefaultDropAction(Qt.MoveAction)
        self.list.model().rowsMoved.connect(self._save_order)
        self.list.itemDoubleClicked.connect(self._on_double)
        v.addWidget(QLabel("Duplo‑clique para extrair:"))
        v.addWidget(self.list, 1)
        # toolbar
        h = QHBoxLayout()
        btn_del = QPushButton("Remove");  btn_del.clicked.connect(self._del)
        btn_ext = QPushButton("Extrair para"); btn_ext.clicked.connect(self._extract)
        btn_close = QPushButton("Fechar"); btn_close.clicked.connect(self.reject)
        h.addWidget(btn_del)
        h.addStretch()
        h.addWidget(btn_ext)
        h.addStretch()
        h.addWidget(btn_close)
        v.addLayout(h)

    def _populate(self):
        self.list.clear(); self.list.addItems(self.vm.list_files())

    # ── slots --------------------------------------------------------------
    def _on_double(self, label):
        # Se vier um QListWidgetItem, pega o texto
        if hasattr(label, "text"):
            label_text = label.text()
        else:
            label_text = str(label)
        # Para qualquer arquivo criptografado (.enc) exporta silenciosamente
        # p/ diretório temporário e devolve o caminho; não abre diálogos.
        if label_text.lower().endswith('.enc'):
            import tempfile, os
            fd, tmp = tempfile.mkstemp(prefix="cg_", suffix=".enc")
            os.close(fd)
            out_path = self.vm.export_file(label_text, Path(tmp).parent)
            try:
                os.chmod(out_path, 0o600)
            except Exception:
                pass
            self.file_selected.emit(out_path)
            self.accept()
        else:
            dest_dir = QFileDialog.getExistingDirectory(
                self, "Salvar em…", str(Path.home())
            )
            if not dest_dir:
                return
            try:
                out = self.vm.export_file(label_text, dest_dir)
                QMessageBox.information(self, "Exportado", f"Arquivo salvo em:\n{out}")
                self.file_selected.emit(out)
                self.accept()
            except Exception as e:
                QMessageBox.critical(self, "Erro", str(e))

    def _extract(self):
        item = self.list.currentItem()
        if not item:
            return
        self._on_double(item)

    # ② guarda a ordem no dict e grava disco
    def _save_order(self, *args):
        new_order = [self.list.item(i).text() for i in range(self.list.count())]
        # mantém apenas a ordem, não altera conteúdo
        ordered = {label: self.vm.db[label] for label in new_order if label in self.vm.db}
        # acrescenta quaisquer rótulos não listados (segurança)
        for k, v in self.vm.db.items():
            if k not in ordered:
                ordered[k] = v
        self.vm.db = ordered
        self.vm._save()

    def _del(self):
        item = self.list.currentItem()
        if not item:
            return
        label = item.text()
        if QMessageBox.question(self, "Confirmar", f"Remover {label} do cofre?") == QMessageBox.Yes:
            self.vm.delete(label); self._populate()

# ═════════════════════════ CLI (retro‑compat) ═══════════════════════════════

def _cli():
    ap = argparse.ArgumentParser("vault.py CLI")
    ap.add_argument("file", type=Path)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    p_add = sub.add_parser("add");      p_add.add_argument("path")
    sub.add_parser("list")
    p_ext = sub.add_parser("extract");   p_ext.add_argument("label"); p_ext.add_argument("dest")
    p_del = sub.add_parser("del");       p_del.add_argument("label")
    sub.add_parser("passwd")
    args = ap.parse_args()

    vm = VaultManager(StorageBackend(args.file))
    pw = SecureMemory(getpass.getpass("Senha mestre: "))
    if args.cmd == "init":
        vm.create(pw); print("Vault criado."); return
    vm.open(pw)
    if args.cmd == "add":
        vm.add_file(args.path); print("Adicionado.")
    elif args.cmd == "list":
        for label in vm.list_files():
            print(label)
    elif args.cmd == "extract":
        out = vm.export_file(args.label, args.dest)
        print(f"Exportado para: {out}")
    elif args.cmd == "del":
        vm.delete(args.label)
        print("Removido.")
    elif args.cmd == "passwd":
        new_pw = SecureMemory(getpass.getpass("Nova senha mestre: "))
        vm.rotate_keys(new_pw)
        print("Senha alterada.")

if __name__ == "__main__":
    _cli()

class WrongPassword(ValueError): ...
class CorruptVault(ValueError): ...
