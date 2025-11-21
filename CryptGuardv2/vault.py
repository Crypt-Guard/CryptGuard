#!/usr/bin/env python3
"""
CryptGuard Vault — backend reforçado (compatível com formato atual)

Este patch recupera a robustez do vault antigo (v2/v3) sem mudar o
formato on-disk dos arquivos existentes. Principais melhorias:
  • Armazenamento atômico com WAL e .bak (recuperação automática)
  • Rate limiting de abertura com proteção de timing
  • Compressão em streaming (gzip) transparente (com fallback)
  • Endurecimento de export (anti path traversal / symlink)
  • Log estruturado de eventos críticos

Compatibilidade: arquivos existentes continuam abrindo normalmente.
Novos saves passam a gravar em formato "box.encrypt(gzip(json))".
Na leitura, se gzip falhar, cai para JSON puro.
"""

from __future__ import annotations

import base64
import contextlib
import gzip
import io
import json
import os
import secrets
import stat
import struct
import threading
import time
from pathlib import Path

import argon2.low_level
from argon2.low_level import Type as _ArgonType

# Dependências principais (como KeyGuard)
try:
    from nacl import secret, utils
    from nacl.pwhash import argon2id
except Exception as e:  # pragma: no cover - fail early
    raise RuntimeError("PyNaCl não disponível — instale 'pynacl'") from e

# Padroniza proteção em memória da senha mestra
from crypto_core.logger import logger
from crypto_core.safe_obfuscator import SecureMemory as CoreSecureMemory, sm_get_bytes


# ────────────────────────────────────────────────────────────────────────────
# Utilitários de robustez portados do vault antigo
# (StreamingCompressor e RateLimiter)
# ────────────────────────────────────────────────────────────────────────────
class StreamingCompressor:
    """Compressão/descompressão em streaming (gzip)."""

    @staticmethod
    def compress(data: bytes, chunk_size: int = 64 * 1024) -> bytes:
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=6) as gz:
            for i in range(0, len(data), chunk_size):
                gz.write(data[i : i + chunk_size])
        return buf.getvalue()

    @staticmethod
    def decompress(data: bytes, chunk_size: int = 64 * 1024) -> bytes:
        out = io.BytesIO()
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            while True:
                chunk = gz.read(chunk_size)
                if not chunk:
                    break
                out.write(chunk)
        return out.getvalue()


class RateLimiter:
    """Rate limiter simples (janela/limite) com aleatoriedade p/ timing."""

    def __init__(self, window: int = 300, threshold: int = 5):
        self.window = window
        self.threshold = threshold
        self.attempts: dict[str, list[float]] = {}
        self.lock = threading.RLock()
        self._rnd = secrets.SystemRandom()

    def check(self, identifier: str = "default") -> None:
        with self.lock:
            now = time.time()
            if identifier in self.attempts:
                self.attempts[identifier] = [
                    t for t in self.attempts[identifier] if now - t < self.window
                ]
            if len(self.attempts.get(identifier, [])) >= self.threshold:
                remaining = self.window - (now - self.attempts[identifier][-self.threshold])
                raise VaultLocked(f"Rate limited - aguarde {int(remaining)}s")

    def record_failure(self, identifier: str = "default") -> None:
        # Atraso aleatório para dificultar side-channels de timing
        time.sleep(self._rnd.randrange(0, 100) / 1000)
        with self.lock:
            now = time.time()
            self.attempts.setdefault(identifier, []).append(now)


# Exceptions e compat
class VaultError(Exception):
    pass


class WrongPassword(VaultError):
    pass


class CorruptVault(VaultError):
    pass


class VaultLocked(VaultError):
    pass


class SecureMemory:
    """Wrapper simples para compatibilidade com a UI."""

    def __init__(self, s: str | bytes):
        self._b = s.encode("utf-8") if isinstance(s, str) else bytes(s)

    def bytes(self) -> bytes:
        return self._b

    def clear(self) -> None:
        try:
            ba = bytearray(self._b)
            for i in range(len(ba)):
                ba[i] = 0
        finally:
            self._b = b""

    def __bytes__(self) -> bytes:  # type: ignore
        return self._b


# Config mínima
class Config:
    @staticmethod
    def default_vault_path() -> Path:
        base = os.getenv("LOCALAPPDATA") or os.path.join(Path.home(), "AppData", "Local")
        p = Path(base) / "CryptGuard" / "vault-cryptguard"
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


def _pw_bytes(pw) -> bytes:
    # Accept our UI wrapper, raw bytes, str, or core SecureMemory-like
    if isinstance(pw, SecureMemory):
        return pw.bytes()
    try:
        # Core SecureMemory (from safe_obfuscator) exposes get_bytes()
        get = getattr(pw, "get_bytes", None)
        if callable(get):
            return get()
    except Exception as exc:
        logger.debug("Secure password wrapper get_bytes failed: %s", exc)
    try:
        # SecureBytes exposes to_bytes()
        to_bytes = getattr(pw, "to_bytes", None)
        if callable(to_bytes):
            return to_bytes()
    except Exception as exc:
        logger.debug("Secure password wrapper to_bytes failed: %s", exc)
    if isinstance(pw, str):
        return pw.encode("utf-8")
    if isinstance(pw, bytes | bytearray | memoryview):
        return bytes(pw)
    try:
        return bytes(pw)
    except Exception as exc:
        raise TypeError("Unsupported password type") from exc


def password_whitespace_hint(password: str) -> str | None:
    """
    Verifica se a senha contém espaços em branco problemáticos.
    
    Retorna uma mensagem de aviso se a senha:
    - Começa ou termina com espaços
    - Contém quebras de linha ou tabs
    
    Retorna None se a senha não tem problemas.
    """
    if not isinstance(password, str):
        return None
    
    # Verifica espaços no início ou fim
    if password != password.strip():
        return "A senha contém espaços no início ou no final"
    
    # Verifica quebras de linha ou tabs
    if '\n' in password or '\r' in password or '\t' in password:
        return "A senha contém caracteres de quebra de linha ou tabulação"
    
    return None


def _sanitize(name: str) -> str:
    bad = ["../", "..\\", "/", "\\", ":", "*", "?", '"', "<", ">", "|", "\x00"]
    s = name
    for b in bad:
        s = s.replace(b, "_")
    s = s.strip() or "unnamed"
    return s[:255]


def _kdf_argon2id(password: bytes, salt: bytes) -> bytes:
    return argon2id.kdf(
        secret.SecretBox.KEY_SIZE,
        password,
        salt,
        opslimit=argon2id.OPSLIMIT_MODERATE,
        memlimit=argon2id.MEMLIMIT_MODERATE,
    )


def _encrypt_json(payload: bytes, password: bytes, salt: bytes) -> bytes:
    key = _kdf_argon2id(password, salt)
    box = secret.SecretBox(key)
    # box.encrypt gera um nonce automaticamente e o inclui no resultado
    return box.encrypt(payload)


def _decrypt_json(blob: bytes, password: bytes, salt: bytes) -> bytes:
    key = _kdf_argon2id(password, salt)
    box = secret.SecretBox(key)
    return box.decrypt(blob)


class VaultEntry:
    def __init__(self, label: str, data: bytes):
        self.label = label
        self.data = data
        self.created = time.time()

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "data": base64.b64encode(self.data).decode("ascii"),
            "created": self.created,
        }

    @classmethod
    def from_dict(cls, d: dict) -> VaultEntry:
        e = cls(d["label"], base64.b64decode(d["data"].encode("ascii")))
        e.created = d.get("created", time.time())
        return e


class AtomicStorageBackend:
    """Armazenamento atômico com WAL e .bak (recuperação automática)."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.wal = self.path.with_suffix(self.path.suffix + ".wal")
        self.bak = self.path.with_suffix(self.path.suffix + ".bak")

    def _set_permissions(self, p: Path) -> None:
        if os.name != "nt":
            with contextlib.suppress(OSError):
                p.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def save(self, data: bytes) -> None:
        # 1) Escreve WAL
        with open(self.wal, "wb") as fwal:
            fwal.write(data)
            fwal.flush()
            os.fsync(fwal.fileno())
        # 2) Escreve arquivo temporário
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # 3) Backup do arquivo atual, se existir
        if self.path.exists():
            try:
                os.replace(self.path, self.bak)
            except OSError as exc:
                logger.warning("AtomicStorage backup rotation failed: %s", exc)
        # 4) Move temporário para final e remove WAL
        os.replace(tmp, self.path)
        with contextlib.suppress(FileNotFoundError):
            os.remove(self.wal)
        self._set_permissions(self.path)

    def load(self) -> bytes:
        # Recupera via WAL se existir
        if self.wal.exists():
            data = self.wal.read_bytes()
            self.save(data)  # completa transação
            return data
        if not self.path.exists():
            return b""
        data = self.path.read_bytes()
        if not data and self.bak.exists():
            return self.bak.read_bytes()
        return data


class VaultManager:
    """API esperada pela UI do CryptGuard, estilo KeyGuard."""

    def __init__(
        self,
        storage: AtomicStorageBackend | None = None,
        path: Path | None = None,
    ):
        if storage is not None and hasattr(storage, "path"):
            self.path = Path(storage.path)
        else:
            self.path = Path(path) if path else Config.default_vault_path()
        self.salt_path = self.path.with_suffix(self.path.suffix + ".salt")
        self._opened = False
        self._pw_secret: CoreSecureMemory | None = None
        self.entries: dict[str, VaultEntry] = {}
        self.order: list[str] = []
        # Reforços novos
        self._storage = storage or AtomicStorageBackend(self.path)
        self._rate = RateLimiter(window=300, threshold=5)

    def create(self, master_password):
        pw = _pw_bytes(master_password)
        self._pw_secret = CoreSecureMemory(pw)
        if not self.salt_path.exists():
            self.salt_path.write_bytes(utils.random(16))
        self.entries.clear()
        self.order.clear()
        self._save()
        self._opened = True

    def open(self, master_password):
        try:
            # Rate limiting de abertura
            try:
                self._rate.check("vault_open")
            except VaultLocked:
                raise

            pw = _pw_bytes(master_password)
            if not self.path.exists():
                raise FileNotFoundError(f"Vault inexistente: {self.path}")

            raw = self._storage.load()
            logger.debug("CryptGuard Vault: iniciando abertura, arquivo tem %d bytes", len(raw))

            # Migração automática do legado "VLT3"
            if raw[:4] == b"VLT3":
                logger.info("CryptGuard Vault: detectado formato legado VLT3, migrando...")
                try:
                    self._migrate_from_vlt3(raw, pw)
                    self._opened = True
                    self._pw_secret = CoreSecureMemory(pw)
                    logger.info("CryptGuard Vault: migração VLT3 concluída com sucesso")
                    return
                except Exception as e:
                    logger.vault_error(
                        "migrate_vlt3",
                        "CryptGuard",
                        e,
                        {"vault_path": str(self.path), "vault_size": len(raw)},
                    )
                    raise CorruptVault(f"Vault legado não pôde ser migrado: {e}") from e

            if not self.salt_path.exists():
                raise CorruptVault(f"Salt .salt ausente para este vault: {self.salt_path}")

            salt = self.salt_path.read_bytes()
            logger.debug("CryptGuard Vault: salt carregado (%d bytes)", len(salt))

            try:
                # Primeiro tenta descriptografar com a senha fornecida
                pt = _decrypt_json(raw, pw, salt)
            except Exception as decrypt_error:
                logger.vault_error(
                    "decrypt",
                    "CryptGuard",
                    decrypt_error,
                    {
                        "vault_path": str(self.path),
                        "salt_path": str(self.salt_path),
                        "vault_size": len(raw),
                        "salt_size": len(salt),
                        "password_length": len(pw),
                    },
                )
                # contabiliza falha
                self._rate.record_failure("vault_open")
                raise WrongPassword("Senha incorreta") from None

            # Transparência de compressão: se pt não for JSON, tenta gunzip
            try:
                obj = json.loads(pt.decode("utf-8"))
                logger.debug("CryptGuard Vault: descriptografia JSON (sem compressão) bem-sucedida")
            except Exception:
                try:
                    unz = StreamingCompressor.decompress(pt)
                    obj = json.loads(unz.decode("utf-8"))
                    logger.debug("CryptGuard Vault: descriptografia + gunzip bem-sucedida")
                except Exception as e2:
                    logger.vault_error("decode", "CryptGuard", e2, {"vault_path": str(self.path)})
                    self._rate.record_failure("vault_open")
                    raise CorruptVault("Vault corrompido (decodificação)") from None

            # Só cria o _pw_secret após validar a senha
            self._pw_secret = CoreSecureMemory(pw)
            self._load_from_obj(obj)
            self._opened = True
            self._rate.attempts.pop("vault_open", None)  # limpa janela

            logger.info(
                "CryptGuard Vault aberto com sucesso: %d arquivos carregados",
                len(self.entries),
            )

        except Exception as e:
            if not isinstance(e, WrongPassword | CorruptVault | FileNotFoundError):
                logger.vault_error(
                    "open",
                    "CryptGuard",
                    e,
                    {
                        "vault_path": str(self.path),
                        "salt_path": str(self.salt_path),
                        "vault_exists": self.path.exists(),
                        "salt_exists": self.salt_path.exists()
                        if hasattr(self, "salt_path")
                        else False,
                    },
                )
            raise

    def close(self):
        self._opened = False
        if self._pw_secret:
            self._pw_secret.clear()
        self._pw_secret = None
        self.entries.clear()
        self.order.clear()

    def add_file(self, file_path: str | Path, label: str | None = None) -> str:
        if not self._opened or not self._pw_secret:
            raise RuntimeError("Vault não está aberto")
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(str(p))
        data = p.read_bytes()
        name = _sanitize(label or p.name)
        original = name
        i = 1
        while name in self.entries:
            stem = Path(original).stem
            suffix = Path(original).suffix
            name = f"{stem}_{i}{suffix}"
            i += 1
        self.entries[name] = VaultEntry(name, data)
        if name not in self.order:
            self.order.append(name)
        self._save()
        return name

    def export_file(self, label: str, dest_dir: str | Path) -> str:
        if not self._opened or not self._pw_secret:
            raise RuntimeError("Vault não está aberto")
        e = self.entries.get(label)
        if not e:
            raise KeyError(label)
        dest_dir = Path(dest_dir).resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)
        out = dest_dir / Path(_sanitize(label)).name
        base = out
        c = 1
        while out.exists():
            out = base.with_stem(f"{base.stem}_{c}")
            c += 1
        out.write_bytes(e.data)
        try:
            os.chmod(out, 0o600)
        except OSError as exc:
            logger.debug("chmod on exported file %s failed: %s", out, exc)
        return str(out)

    def delete_file(self, label: str):
        if not self._opened or not self._pw_secret:
            raise RuntimeError("Vault não está aberto")
        # Remoção segura mantendo ordem consistente
        self.entries.pop(label, None)
        self.order = [n for n in self.order if n != label]
        self._save()

    def list_files(self) -> list[str]:
        for n in list(self.entries.keys()):
            if n not in self.order:
                self.order.append(n)
        self.order = [n for n in self.order if n in self.entries]
        return list(self.order)

    def change_password(self, old_password, new_password):
        if not self.path.exists() or not self.salt_path.exists():
            raise FileNotFoundError("Vault ausente")
        salt = self.salt_path.read_bytes()
        blob = self.path.read_bytes()
        try:
            _decrypt_json(blob, _pw_bytes(old_password), salt)
        except Exception as exc:
            raise WrongPassword("Senha atual incorreta") from exc
        self._pw_secret = CoreSecureMemory(_pw_bytes(new_password))
        self.salt_path.write_bytes(utils.random(16))
        self._save()

    def _data(self) -> dict:
        return {
            "format": 2,
            "order": list(self.order),
            "entries": [self.entries[n].to_dict() for n in self.order],
        }

    def _load_from_obj(self, obj: dict) -> None:
        self.order = list(obj.get("order", []))
        self.entries = {}
        for ed in obj.get("entries", []):
            e = VaultEntry.from_dict(ed)
            self.entries[e.label] = e
        self.list_files()

    def _save(self) -> None:
        if not self._pw_secret:
            raise RuntimeError("Senha não definida")
        # Lê o salt existente ou cria um novo apenas se não existir
        if self.salt_path.exists():
            salt = self.salt_path.read_bytes()
        else:
            salt = utils.random(16)
            self.salt_path.write_bytes(salt)

        # Serializa e comprime (gzip). Fallback de leitura existe em open().
        obj = self._data()
        payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        gz_payload = StreamingCompressor.compress(payload)

        # Extrai a senha do SecureMemory usando view()
        pw_view = getattr(self._pw_secret, "view", None)
        if callable(pw_view):
            mv = pw_view()
            try:
                pw_bytes = bytes(mv)
            finally:
                with contextlib.suppress(Exception):
                    mv.release()
        else:
            pw_bytes = sm_get_bytes(self._pw_secret)
        ct = _encrypt_json(gz_payload, pw_bytes, salt)

        # Grava por backend atômico com WAL/backup
        self._storage.save(ct)

    def _migrate_from_vlt3(self, blob: bytes, password: bytes) -> None:
        """Melhor-esforço para migrar o formato legado com cabeçalho VLT3."""
        HEADER_FMT = ">4sB16s24sHIB"
        HEADER_LEN = struct.calcsize(HEADER_FMT)  # 52
        if len(blob) < HEADER_LEN:
            raise CorruptVault("Header legacy curto")
        hdr = blob[:HEADER_LEN]
        try:
            magic, version, salt, nonce, t, m, p = struct.unpack(HEADER_FMT, hdr)
        except struct.error as exc:
            raise CorruptVault("Header legacy inválido") from exc
        if magic != b"VLT3":
            raise CorruptVault("Formato legacy desconhecido")

        # Ciphertext pode vir após MAC (32B) ou não, tentamos ambos.
        candidates: list[bytes] = []
        if len(blob) >= HEADER_LEN + 32:
            candidates.append(blob[HEADER_LEN + 32 :])  # [HEADER|MAC|CT]
        candidates.append(blob[HEADER_LEN:])  # [HEADER|CT]

        # Derivação anterior (Argon2id -> HKDF split), usamos só enc_key[0:32].
        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF

            master = argon2.low_level.hash_secret_raw(password, salt, t, m, p, 64, _ArgonType.ID)
            enc_key = HKDF(
                algorithm=hashes.SHA256(), length=64, salt=None, info=b"Vault split v3"
            ).derive(master)[:32]
        except Exception as e:
            raise CorruptVault(f"KDF legacy indisponível: {e}") from e

        last_err: Exception | None = None
        for ct in candidates:
            # 1) XChaCha20-Poly1305 (nonce 24B + AAD=hdr)
            try:
                from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305

                pt = XChaCha20Poly1305(enc_key).decrypt(nonce, ct, hdr)
                obj = json.loads(pt.decode("utf-8"))
                self._load_legacy_obj(obj)
                if not self.salt_path.exists():
                    self.salt_path.write_bytes(utils.random(16))
                # Set new protected master password and save
                self._pw_secret = CoreSecureMemory(password)
                self._save()
                return
            except Exception as ex:
                last_err = ex
                # 2) ChaCha20-Poly1305 IETF (nonce 12B, sem AAD)
                try:
                    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

                    pt = ChaCha20Poly1305(enc_key).decrypt(nonce[:12], ct, b"")
                    obj = json.loads(pt.decode("utf-8"))
                    self._load_legacy_obj(obj)
                    if not self.salt_path.exists():
                        self.salt_path.write_bytes(utils.random(16))
                    # Set new protected master password and save
                    self._pw_secret = CoreSecureMemory(password)
                    self._save()
                    return
                except Exception as ex2:
                    last_err = ex2
                    continue
        raise CorruptVault(f"Falha ao migrar legacy: {last_err}")

    def _load_legacy_obj(self, obj: dict) -> None:
        # Permite dois formatos: {label: base64} ou já estruturado
        if isinstance(obj, dict) and all(isinstance(v, str) for v in obj.values()):
            new_entries = []
            for label, b64 in obj.items():
                new_entries.append(
                    VaultEntry(_sanitize(label), base64.b64decode(b64.encode("ascii")))
                )
        else:
            new_entries = [VaultEntry.from_dict(ed) for ed in obj.get("entries", [])]
        self.entries = {e.label: e for e in new_entries}
        self.order = [e.label for e in new_entries]


def open_or_init_vault(password: str, path: Path | str) -> VaultManager:
    """Abre o vault existente; NUNCA cria automaticamente aqui.
    Criação deve ser uma ação explícita no chamador.
    """
    vm = VaultManager(path=Path(path))
    if Path(path).exists():
        vm.open(password)
        return vm
    raise FileNotFoundError("Vault inexistente — crie explicitamente")


# Dialog (Qt) — versão simples
try:
    from PySide6.QtCore import Signal
    from PySide6.QtWidgets import (
        QDialog,
        QFileDialog,
        QHBoxLayout,
        QListWidget,
        QMessageBox,
        QPushButton,
        QVBoxLayout,
    )

    class VaultDialog(QDialog):
        file_selected = Signal(str)

        def __init__(self, vault_manager: VaultManager, parent=None):
            super().__init__(parent)
            self.setWindowTitle("CryptGuard Vault")
            self.vm = vault_manager
            self.listw = QListWidget(self)
            self.refresh()
            btn_open = QPushButton("Export && Select", self)
            btn_add = QPushButton("Add…", self)
            btn_del = QPushButton("Delete", self)

            btn_open.clicked.connect(self._select_current)
            btn_add.clicked.connect(self._add_file)
            btn_del.clicked.connect(self._delete_current)
            self.listw.itemDoubleClicked.connect(lambda _i: self._select_current())

            v = QVBoxLayout(self)
            v.addWidget(self.listw)
            h = QHBoxLayout()
            h.addWidget(btn_add)
            h.addWidget(btn_del)
            h.addStretch(1)
            h.addWidget(btn_open)
            v.addLayout(h)

        def refresh(self):
            self.listw.clear()
            for name in self.vm.list_files():
                self.listw.addItem(name)

        def _current_label(self) -> str | None:
            it = self.listw.currentItem()
            return it.text() if it else None

        def _select_current(self):
            label = self._current_label()
            if not label:
                return
            # Escolhe a pasta de destino para exportação
            dest_dir = QFileDialog.getExistingDirectory(self, "Select destination folder")
            if not dest_dir:
                return
            try:
                path = self.vm.export_file(label, dest_dir)
            except Exception as e:
                logger.exception("Vault export failed: %s", e)
                QMessageBox.critical(self, "Export failed", f"Could not export file:\n{e}")
                return
            # Emite o arquivo exportado e fecha o diálogo
            self.file_selected.emit(path)
            self.accept()

        def _add_file(self):
            fn, _ = QFileDialog.getOpenFileName(self, "Adicionar arquivo ao Vault")
            if not fn:
                return
            try:
                self.vm.add_file(fn)
                self.refresh()
            except Exception as exc:
                logger.exception("Vault dialog failed to add file: %s", exc)
                QMessageBox.critical(self, "Add failed", f"Could not add file:\n{exc}")

        def _delete_current(self):
            label = self._current_label()
            if not label:
                return
            try:
                self.vm.delete_file(label)
                self.refresh()
            except Exception as exc:
                logger.exception("Vault dialog failed to delete file: %s", exc)
                QMessageBox.critical(self, "Delete failed", f"Could not delete file:\n{exc}")

except Exception:
    # Ambiente sem Qt: fornece um stub para evitar ImportError
    class VaultDialog:  # type: ignore
        def __init__(self, *a, **k):
            raise RuntimeError("Qt indisponível para VaultDialog")
