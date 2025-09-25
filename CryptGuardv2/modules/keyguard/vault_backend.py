#!/usr/bin/env python3
"""
KeyGuard Vault backend (Qt-agnostic) – versão reforçada

Este patch adiciona robustez operacional sem alterar o formato on‑disk
do KeyGuard (salt embutido + header "KGV1" + SecretBox ciphertext).

Melhorias principais:
  • Armazenamento atômico com WAL e .bak (recuperação automática)
  • Rate limiting com jitter em aberturas (mitiga guessing/timing)
  • Compressão transparente (gzip) antes da cifra (+ fallback na leitura)
  • Permissões restritivas pós-gravação (POSIX)
  • Métodos faltantes p/ UI: reorder() e update_all_passwords()
"""

from __future__ import annotations

import base64
import gzip
import io
import json
import os
import secrets
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from nacl import pwhash, secret, utils

from crypto_core.log_utils import log_best_effort
from crypto_core.logger import logger

# Secure memory / obfuscator
try:
    from crypto_core.secure_bytes import SecureBytes as SecureMemory  # type: ignore
except Exception:

    class SecureMemory:
        def __init__(self, b: bytes):
            self._b = bytearray(b)

        def to_bytes(self) -> bytes:
            return bytes(self._b)

        def clear(self):
            self._b[:] = b"\x00" * len(self._b)


try:
    from crypto_core.key_obfuscator import KeyObfuscator  # type: ignore
except Exception:

    class KeyObfuscator:
        def __init__(self, sm: SecureMemory):
            self._sm = sm

        def obfuscate(self):
            pass

        def deobfuscate(self):
            pass

        def clear(self):
            self._sm.clear()


from crypto_core.safe_obfuscator import sm_get_bytes  # extração segura


# Helper para extrair bytes do SecureMemory SEM usar to_bytes()
def _sm_bytes(sm) -> bytes:
    return sm_get_bytes(sm)


# P1.1: Import do decorator de segurança
try:
    from crypto_core.secretenv import no_str_secrets
except ImportError:
    # Fallback se não estiver disponível
    def no_str_secrets(*args):
        def decorator(func):
            return func

        return decorator


class ObfuscatedSecret:
    def __init__(self, sm: SecureMemory):
        self._sm = sm
        # Não usar KeyObfuscator pois ele limpa o SecureMemory original
        # causando problemas na extração de bytes
        self._ko = None

    def expose(self):
        class _Ctx:
            def __init__(self, outer):
                self.o = outer

            def __enter__(self):
                # Simplesmente retorna o SecureMemory sem obfuscação
                return self.o._sm

            def __exit__(self, *a):
                # Sem obfuscação ativa, não há o que fazer
                pass

        return _Ctx(self)

    def clear(self):
        try:
            self._sm.clear()
        except Exception as exc:
            log_best_effort(__name__, exc)

    def reset(self, sm: SecureMemory):
        self.clear()
        self._sm = sm


@dataclass
class VaultEntry:
    name: str
    password_b64: str
    metadata: dict = field(default_factory=dict)
    created: float = field(default_factory=time.time)
    modified: float = field(default_factory=time.time)


class VaultError(Exception): ...


class WrongPassword(VaultError): ...


class CorruptVault(VaultError): ...


class VaultManager:
    """Gerencia o arquivo de vault do KeyGuard (robustecido)."""

    class _RateLimiter:
        """Janela deslizante simples com leve jitter para mitigar timing."""

        def __init__(self, window: int = 300, threshold: int = 5):
            self.window = window
            self.threshold = threshold
            self._lock = threading.RLock()
            self._attempts: dict[str, list[float]] = {}
            self._rnd = secrets.SystemRandom()

        def check(self, key: str) -> None:
            now = time.time()
            with self._lock:
                arr = self._attempts.get(key, [])
                arr = [t for t in arr if now - t < self.window]
                self._attempts[key] = arr
                if len(arr) >= self.threshold:
                    remaining = int(self.window - (now - arr[-self.threshold]))
                    raise CorruptVault(f"Rate limited — aguarde {remaining}s")

        def record_failure(self, key: str) -> None:
            # jitter milissegundos para ofuscar timing
            time.sleep(self._rnd.randrange(0, 100) / 1000.0)
            with self._lock:
                self._attempts.setdefault(key, []).append(time.time())

        def reset(self, key: str) -> None:
            with self._lock:
                self._attempts.pop(key, None)

    class _AtomicStorage:
        """WAL + .bak + tmp => gravação atômica com recuperação automática."""

        def __init__(self, path: Path):
            self.path = Path(path)
            self.wal = self.path.with_suffix(self.path.suffix + ".wal")
            self.bak = self.path.with_suffix(self.path.suffix + ".bak")

        def _set_permissions(self, p: Path) -> None:
            if os.name != "nt":
                try:
                    p.chmod(stat.S_IRUSR | stat.S_IWUSR)
                except Exception as exc:
                    log_best_effort(__name__, exc)

        def save(self, data: bytes) -> None:
            os.makedirs(self.path.parent, exist_ok=True)
            # 1) WAL
            with open(self.wal, "wb") as fwal:
                fwal.write(data)
                fwal.flush()
                os.fsync(fwal.fileno())
            # 2) tmp
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            # 3) backup do atual, se existir
            if self.path.exists():
                try:
                    os.replace(self.path, self.bak)
                except Exception as exc:
                    log_best_effort(__name__, exc)
            # 4) finalize
            os.replace(tmp, self.path)
            try:
                os.remove(self.wal)
            except FileNotFoundError as exc:
                log_best_effort(__name__, exc)
            self._set_permissions(self.path)

        def load(self) -> bytes:
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

    def __init__(self, path: os.PathLike | None = None):
        self.path = Path(path or self._default_path())
        self._opened = False
        self._pw_secret: ObfuscatedSecret | None = None
        self.entries: dict[str, VaultEntry] = {}
        self.entry_order: list[str] = []
        self.autosave = True
        # novos reforços
        self._store = self._AtomicStorage(self.path)
        self._rate = self._RateLimiter(window=300, threshold=5)

    # ---------- API pública ----------
    @no_str_secrets("master_password")
    def create(self, master_password: bytes):
        try:
            self._pw_secret = ObfuscatedSecret(SecureMemory(master_password))
            self.entries.clear()
            self.entry_order.clear()
            self._save()
            self._opened = True
            logger.info("KeyGuard Vault criado com sucesso em %s", self.path)
        except Exception as e:
            logger.vault_error(
                "create",
                "KeyGuard",
                e,
                {
                    "vault_path": str(self.path),
                    "entries_count": len(self.entries),
                    "password_length": len(master_password) if master_password else 0,
                },
            )
            raise

    @no_str_secrets("master_password")
    def open(self, master_password: bytes):
        try:
            self._rate.check("open")
            if not self.path.exists():
                raise FileNotFoundError(f"Vault inexistente: {self.path}")

            raw = self._store.load()
            if not raw:
                raise CorruptVault(f"Arquivo vazio: {self.path}")

            logger.debug("KeyGuard Vault: iniciando abertura, arquivo tem %d bytes", len(raw))

            # Primeiro tenta descriptografar para validar a senha
            obj = self._decrypt_json_inline_salt(raw, master_password)
            # Só depois de validar, cria o ObfuscatedSecret
            self._pw_secret = ObfuscatedSecret(SecureMemory(master_password))
            self._load_from_obj(obj)
            self._opened = True
            self._rate.reset("open")

            logger.info(
                "KeyGuard Vault aberto com sucesso: %d entradas carregadas",
                len(self.entries),
            )

        except Exception as e:
            # conta falha para rate-limit em casos de senha/decifração
            try:
                if isinstance(e, WrongPassword | CorruptVault):
                    self._rate.record_failure("open")
            except Exception as exc:
                log_best_effort(__name__, exc)
            logger.vault_error(
                "open",
                "KeyGuard",
                e,
                {
                    "vault_path": str(self.path),
                    "vault_exists": self.path.exists() if hasattr(self, "path") else False,
                    "vault_size": len(raw) if "raw" in locals() else 0,
                    "password_length": len(master_password) if master_password else 0,
                    "vault_opened": getattr(self, "_opened", False),
                },
            )
            raise

    def close(self):
        self._opened = False
        if self._pw_secret:
            self._pw_secret.clear()
        self._pw_secret = None
        self.entries.clear()
        self.entry_order.clear()

    def list_entries(self) -> list[str]:
        return list(self.entry_order)

    def get_entry(self, name: str) -> VaultEntry | None:
        return self.entries.get(name)

    def add_or_update_entry(self, name: str, password: str, metadata: dict | None = None):
        enc = base64.b64encode(password.encode("utf-8")).decode("ascii")
        now = time.time()
        if name in self.entries:
            e = self.entries[name]
            e.password_b64 = enc
            e.metadata = metadata or {}
            e.modified = now
        else:
            e = VaultEntry(
                name=name,
                password_b64=enc,
                metadata=metadata or {},
                created=now,
                modified=now,
            )
            self.entries[name] = e
            self.entry_order.append(name)
        self._autosave()

    # compat
    def upsert_entry(self, name: str, password: str, metadata: dict | None = None):
        return self.add_or_update_entry(name, password, metadata)

    def delete_entry(self, name: str):
        if name in self.entries:
            del self.entries[name]
            if name in self.entry_order:
                self.entry_order.remove(name)
            self._autosave()

    @no_str_secrets("new_password")
    def change_master_password(self, new_password: bytes):
        self._pw_secret = ObfuscatedSecret(SecureMemory(new_password))
        self._save()  # regrava com novo salt embutido

    def export_json(self) -> str:
        return json.dumps(self._data(), ensure_ascii=False, separators=(",", ":"))

    def import_json(self, s: str):
        obj = json.loads(s)
        self._load_from_obj(obj)
        self._autosave()

    # ---------- internos ----------
    def _default_path(self) -> str:
        # Padronizado para ficar junto com o CryptGuard vault
        base = os.environ.get("LOCALAPPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Local"
        )
        vault_dir = os.path.join(base, "CryptGuard")
        os.makedirs(vault_dir, exist_ok=True)
        return os.path.join(vault_dir, "vault-keyguard")

    def _data(self) -> dict:
        return {
            "format": 1,
            "order": self.entry_order,
            "entries": {k: e.__dict__ for k, e in self.entries.items()},
        }

    def _load_from_obj(self, obj: dict):
        self.entry_order = list(obj.get("order", []))
        ents = obj.get("entries", {})
        self.entries = {k: VaultEntry(**v) for k, v in ents.items()}

    def _autosave(self):
        if self.autosave and self._pw_secret:
            try:
                self._save()
            except Exception as exc:
                log_best_effort(__name__, exc)

    def _save(self):
        try:
            if not self._pw_secret:
                raise RuntimeError("Senha não definida")

            logger.debug("KeyGuard Vault: iniciando salvamento de %d entradas", len(self.entries))

            with self._pw_secret.expose() as sm:
                extracted_bytes = _sm_bytes(sm)
                if not extracted_bytes:
                    raise RuntimeError("Falha ao extrair senha do ObfuscatedSecret")
                final_data = self._encrypt_json_inline_salt(self._data(), extracted_bytes)

            self._store.save(final_data)

            logger.debug("KeyGuard Vault salvo com sucesso: %d bytes escritos", len(final_data))

        except Exception as e:
            logger.vault_error(
                "save",
                "KeyGuard",
                e,
                {
                    "vault_path": str(self.path),
                    "entries_count": len(self.entries),
                    "has_password_secret": self._pw_secret is not None,
                    "vault_dir_exists": self.path.parent.exists()
                    if hasattr(self.path, "parent")
                    else False,
                },
            )
            raise

    # Cifra com salt embutido no arquivo (salt|header|ciphertext)
    # P0.2: Adicionado versionamento dos parâmetros pwhash
    def _encrypt_json_inline_salt(self, obj: dict, password: bytes):
        # P1.2: Usar SENSITIVE por padrão (em vez de MODERATE)
        opslimit = pwhash.argon2id.OPSLIMIT_SENSITIVE
        memlimit = pwhash.argon2id.MEMLIMIT_SENSITIVE

        salt = utils.random(pwhash.argon2id.SALTBYTES)
        key = pwhash.argon2id.kdf(
            secret.SecretBox.KEY_SIZE,
            password,
            salt,
            opslimit=opslimit,
            memlimit=memlimit,
        )
        box = secret.SecretBox(key)
        # Compacta JSON para reduzir I/O e memória; leitura tem fallback
        plain = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        gz_plain = io.BytesIO()
        with gzip.GzipFile(fileobj=gz_plain, mode="wb", compresslevel=6) as gz:
            gz.write(plain)
        enc = box.encrypt(gz_plain.getvalue())

        # Criar header versionado com parâmetros KDF
        header = json.dumps(
            {"v": 1, "kdf": "argon2id", "opsl": int(opslimit), "meml": int(memlimit)},
            separators=(",", ":"),
        ).encode("utf-8")

        # Formato: MAGIC(4) + header_len(2) + header + ciphertext
        HEADER_MAGIC = b"KGV1"
        header_and_ct = HEADER_MAGIC + len(header).to_bytes(2, "big") + header + bytes(enc)

        # Retorna formato correto: salt concatenado com resto
        return salt + header_and_ct

    def _decrypt_json_inline_salt(self, raw: bytes, password: bytes) -> dict:
        from nacl import pwhash, secret

        try:
            SALT_SIZE = pwhash.argon2id.SALTBYTES
            HEADER_MAGIC = b"KGV1"

            logger.debug("KeyGuard: iniciando descriptografia, arquivo tem %d bytes", len(raw))

            if len(raw) < SALT_SIZE + secret.SecretBox.NONCE_SIZE:
                raise CorruptVault(
                    f"Arquivo muito curto: {len(raw)} bytes, mínimo {SALT_SIZE + secret.SecretBox.NONCE_SIZE}"
                )

            salt, rest = raw[:SALT_SIZE], raw[SALT_SIZE:]
            logger.debug(
                "KeyGuard: salt extraído (%d bytes), resto (%d bytes)",
                len(salt),
                len(rest),
            )

            # P0.2: Detectar formato versionado vs legado
            if rest.startswith(HEADER_MAGIC):
                # Formato novo com header versionado
                if len(rest) < 6:  # MAGIC(4) + header_len(2)
                    raise CorruptVault("Header versionado incompleto")

                hlen = int.from_bytes(rest[4:6], "big")
                if len(rest) < 6 + hlen:
                    raise CorruptVault("Header truncado")

                header_bytes = rest[6 : 6 + hlen]
                encrypted = rest[6 + hlen :]

                try:
                    meta = json.loads(header_bytes.decode("utf-8"))
                    opslimit = int(meta.get("opsl", pwhash.argon2id.OPSLIMIT_MODERATE))
                    memlimit = int(meta.get("meml", pwhash.argon2id.MEMLIMIT_MODERATE))
                    logger.debug(
                        "KeyGuard: formato versionado v%d, opslimit=%d, memlimit=%d",
                        meta.get("v", 0),
                        opslimit,
                        memlimit,
                    )
                except json.JSONDecodeError as exc:
                    raise CorruptVault("Header versionado com JSON inválido") from exc
            else:
                # Formato legado (compatibilidade)
                encrypted = rest
                opslimit = pwhash.argon2id.OPSLIMIT_MODERATE
                memlimit = pwhash.argon2id.MEMLIMIT_MODERATE
                logger.debug("KeyGuard: formato legado detectado")

            # Derivar chave
            key = pwhash.argon2id.kdf(
                secret.SecretBox.KEY_SIZE,
                password,
                salt,
                opslimit=opslimit,
                memlimit=memlimit,
            )
            logger.debug("KeyGuard: chave derivada com sucesso (%d bytes)", len(key))

            box = secret.SecretBox(key)
            plain = box.decrypt(encrypted)
            logger.debug(
                "KeyGuard: descriptografia bem-sucedida, dados descriptografados (%d bytes)",
                len(plain),
            )

            # Tenta JSON direto; se falhar, fallback para gunzip -> JSON
            try:
                result = json.loads(plain.decode("utf-8"))
                logger.debug("KeyGuard: JSON direto (sem gzip)")
            except Exception:
                try:
                    result = json.loads(gzip.decompress(plain).decode("utf-8"))
                    logger.debug("KeyGuard: JSON via gzip (fallback)")
                except Exception as e2:
                    logger.exception_with_context(
                        "KeyGuard: falha ao decodificar JSON (direto e gzip)",
                        e2,
                        {"raw_length": len(raw)},
                    )
                    raise CorruptVault("Dados corrompidos (decodificação)") from e2

            logger.debug(
                "KeyGuard: JSON parseado com sucesso, %d entradas encontradas",
                len(result.get("entries", {})),
            )

            return result

        except json.JSONDecodeError as e:
            logger.exception_with_context(
                "KeyGuard: Erro ao parsear JSON após descriptografia",
                e,
                {
                    "raw_length": len(raw),
                    "password_length": len(password),
                    "decrypted_data_sample": plain[:100].decode("utf-8", errors="replace")
                    if "plain" in locals()
                    else None,
                },
            )
            raise CorruptVault(f"JSON inválido após descriptografia: {e}") from e
        except Exception as e:
            # Se for erro de senha, logar com menos detalhes
            if "verification" in str(e).lower() or "decrypt" in str(e).lower():
                logger.warning(
                    "KeyGuard Vault: senha incorreta ou arquivo corrompido - %s",
                    type(e).__name__,
                )
                raise WrongPassword("Senha incorreta ou arquivo corrompido") from e
            else:
                logger.exception_with_context(
                    "KeyGuard: Erro inesperado na descriptografia",
                    e,
                    {
                        "raw_length": len(raw),
                        "password_length": len(password),
                        "salt_size": SALT_SIZE,
                        "min_required_size": SALT_SIZE + secret.SecretBox.NONCE_SIZE,
                    },
                )
                raise

    # -------------------- Utilidades para UI --------------------
    def reorder(self, new_order: list[str]) -> None:
        """Reordena mantendo apenas labels existentes; salva se autosave."""
        order = []
        seen = set()
        for name in new_order:
            if name in self.entries and name not in seen:
                order.append(name)
                seen.add(name)
        # adiciona os restantes que ficaram de fora
        for name in self.entry_order:
            if name not in seen and name in self.entries:
                order.append(name)
        self.entry_order = order
        self._autosave()

    def update_all_passwords(
        self, generator, *, length: int = 20, charset_key: str = "full"
    ) -> int:
        """Atualiza todas as senhas usando um gerador (compatível com UI)."""
        cnt = 0
        for name in list(self.entry_order):
            try:
                pwd = generator.generate(length=length, charset_key=charset_key)
                self.add_or_update_entry(name, pwd, metadata=self.entries[name].metadata)
                cnt += 1
            except Exception:
                continue
        return cnt
