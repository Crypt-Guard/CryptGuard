"""
Formato de Secure Container (.vault) para compartilhamento seguro.

Formato do arquivo:
  HEADER:
    - MAGIC: b"CGSC1\0" (6 bytes)
    - VERSION: u8 = 1
    - ALG_ID: u8 = 0x01 (XChaCha20-Poly1305 SecretStream)
    - KDF_LEN: u16 (big-endian) - tamanho do KDF_JSON
    - KDF_JSON: UTF-8 minificado com parâmetros Argon2id
    - SALT: 16 bytes (embutido, usado no Argon2id)

  CRIPTOGRAMA (SecretStream):
    - Sequência TLV de entradas:
      * ENTRY_HDR_LEN (u32, big-endian)
      * ENTRY_HDR_JSON (UTF-8)
      * ENTRY_DATA_LEN (u64, big-endian)
      * ENTRY_DATA (bytes)
    - TAG_FINAL encerra o stream

Segurança:
  - SALT embutido (nunca sidecar)
  - Header completo como AAD (Authenticated Additional Data)
  - Argon2id para derivação de chave
  - XChaCha20-Poly1305 SecretStream para criptografia
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import struct
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from argon2.low_level import Type as ArgonType
from argon2.low_level import hash_secret_raw
from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_init_push,
    crypto_secretstream_xchacha20poly1305_pull,
    crypto_secretstream_xchacha20poly1305_push,
    crypto_secretstream_xchacha20poly1305_state,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
)

from crypto_core.logger import logger

from .storage_atomic import acquire_lock, atomic_save

# Constantes do formato
MAGIC = b"CGSC1\x00"
VERSION = 1
ALG_ID = 0x01  # XChaCha20-Poly1305 SecretStream
SALT_LEN = 16  # bytes
SS_HEADER_BYTES = 24  # libsodium SecretStream header

# Tags do SecretStream
TAG_MESSAGE = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
TAG_FINAL = crypto_secretstream_xchacha20poly1305_TAG_FINAL

# Perfis KDF
KDF_PROFILES = {
    "moderate": {"time_cost": 3, "memory_cost": 64 * 1024, "parallelism": 2},
    "strong": {"time_cost": 5, "memory_cost": 128 * 1024, "parallelism": 4},
}


class ContainerError(Exception):
    """Erro genérico de container."""

    pass


class WrongPasswordError(ContainerError):
    """Senha incorreta ou arquivo corrompido."""

    pass


class CorruptContainerError(ContainerError):
    """Container corrompido."""

    pass


@dataclass
class ContainerEntry:
    """Representa uma entrada no container."""

    type: Literal["cg_file", "kg_secret", "manifest"]
    id: str
    name: str
    meta: dict[str, Any] = field(default_factory=dict)
    data: bytes = b""
    created_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    modified_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> dict[str, Any]:
        """Converte para dicionário (sem data, apenas metadados)."""
        return {
            "type": self.type,
            "id": self.id,
            "name": self.name,
            "meta": self.meta,
            "size": len(self.data),
            "created_at": self.created_at,
            "modified_at": self.modified_at,
        }


def _canonical_json(obj: Any) -> bytes:
    """Serializa JSON de forma canônica (determinística)."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _u16_be(n: int) -> bytes:
    """Codifica u16 big-endian."""
    return struct.pack(">H", n)


def _u32_be(n: int) -> bytes:
    """Codifica u32 big-endian."""
    return struct.pack(">I", n)


def _u64_be(n: int) -> bytes:
    """Codifica u64 big-endian."""
    return struct.pack(">Q", n)


def _read_exact(f, n: int) -> bytes:
    """Lê exatamente n bytes ou lança ValueError."""
    buf = b""
    while len(buf) < n:
        chunk = f.read(n - len(buf))
        if not chunk:
            raise ValueError("Truncated stream: expected more bytes")
        buf += chunk
    return buf


def derive_key_argon2id(
    password: bytes, salt: bytes, time_cost: int, memory_cost: int, parallelism: int
) -> bytes:
    """
    Deriva chave de 32 bytes usando Argon2id.

    Args:
        password: Senha em bytes
        salt: Salt (mínimo 16 bytes)
        time_cost: Custo de tempo (iterações)
        memory_cost: Custo de memória em KiB
        parallelism: Grau de paralelismo

    Returns:
        Chave de 32 bytes

    Raises:
        ValueError: Parâmetros inválidos
    """
    if len(salt) < 16:
        raise ValueError("Salt deve ter pelo menos 16 bytes")

    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=ArgonType.ID,
    )


def build_header(kdf_profile: str, salt: bytes) -> tuple[bytes, dict[str, Any]]:
    """
    Constrói o header do container.

    Args:
        kdf_profile: Nome do perfil KDF ('moderate' ou 'strong')
        salt: Salt de 16 bytes

    Returns:
        (header_bytes, kdf_obj) - Header completo e objeto KDF

    Raises:
        ValueError: Perfil desconhecido ou salt inválido
    """
    if kdf_profile not in KDF_PROFILES:
        raise ValueError(f"Perfil KDF desconhecido: {kdf_profile}")

    if len(salt) != SALT_LEN:
        raise ValueError(f"Salt deve ter {SALT_LEN} bytes")

    # Construir objeto KDF
    profile_params = KDF_PROFILES[kdf_profile]
    kdf_obj = {
        "algo": "argon2id",
        "opslimit": kdf_profile,
        "memlimit": kdf_profile,
        "salt_hex": salt.hex(),
        "time_cost": profile_params["time_cost"],
        "memory_cost": profile_params["memory_cost"],
        "parallelism": profile_params["parallelism"],
    }

    kdf_json = _canonical_json(kdf_obj)
    kdf_len = len(kdf_json)

    if kdf_len > 0xFFFF:
        raise ValueError("KDF JSON muito grande")

    # Montar header: MAGIC | VERSION | ALG_ID | KDF_LEN | KDF_JSON | SALT
    header = b"".join([
        MAGIC,
        struct.pack(">B", VERSION),
        struct.pack(">B", ALG_ID),
        _u16_be(kdf_len),
        kdf_json,
        salt,
    ])

    return header, kdf_obj


def parse_header(header_bytes: bytes) -> tuple[dict[str, Any], bytes, int]:
    """
    Parse do header do container.

    Args:
        header_bytes: Bytes do início do arquivo

    Returns:
        (kdf_obj, salt, offset) - Objeto KDF, salt e offset após o header

    Raises:
        ValueError: Header inválido
    """
    if len(header_bytes) < len(MAGIC) + 4:
        raise ValueError("Header truncado")

    # Verificar MAGIC
    if not header_bytes.startswith(MAGIC):
        raise ValueError("MAGIC inválido - não é um container CGSC1")

    offset = len(MAGIC)

    # VERSION
    version = struct.unpack_from(">B", header_bytes, offset)[0]
    offset += 1
    if version != VERSION:
        raise ValueError(f"Versão não suportada: {version}")

    # ALG_ID
    alg_id = struct.unpack_from(">B", header_bytes, offset)[0]
    offset += 1
    if alg_id != ALG_ID:
        raise ValueError(f"Algoritmo não suportado: {alg_id}")

    # KDF_LEN
    if len(header_bytes) < offset + 2:
        raise ValueError("Header truncado (KDF_LEN)")
    kdf_len = struct.unpack_from(">H", header_bytes, offset)[0]
    offset += 2
    if kdf_len == 0 or kdf_len > 0xFFFF:
        raise ValueError("KDF JSON length inválido")

    # KDF_JSON
    if len(header_bytes) < offset + kdf_len:
        raise ValueError("Header truncado (KDF_JSON)")
    kdf_json_bytes = header_bytes[offset : offset + kdf_len]
    offset += kdf_len

    try:
        kdf_obj = json.loads(kdf_json_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError("KDF JSON inválido") from e

    # SALT
    if len(header_bytes) < offset + SALT_LEN:
        raise ValueError("Header truncado (SALT)")
    salt = header_bytes[offset : offset + SALT_LEN]
    offset += SALT_LEN

    return kdf_obj, salt, offset


class SecureContainerWriter:
    """
    Writer para criar secure containers.

    Uso:
        with SecureContainerWriter(path, password, "moderate") as writer:
            writer.add_manifest(manifest_dict)
            writer.add_cg_file(name="test.txt", data=b"...", meta={})
            writer.finalize()
    """

    def __init__(self, path: Path, password: bytes, kdf_profile: str = "moderate"):
        """
        Inicializa writer.

        Args:
            path: Caminho do arquivo .vault
            password: Senha em bytes
            kdf_profile: Perfil KDF ('moderate' ou 'strong')

        Raises:
            ValueError: Parâmetros inválidos
        """
        self.path = Path(path)
        self.password = password
        self.kdf_profile = kdf_profile

        # Gerar salt aleatório
        self.salt = os.urandom(SALT_LEN)

        # Derivar chave
        profile_params = KDF_PROFILES[kdf_profile]
        logger.info(
            "Derivando chave do container com Argon2id (profile=%s, t=%d, m=%d KiB, p=%d)",
            kdf_profile,
            profile_params["time_cost"],
            profile_params["memory_cost"],
            profile_params["parallelism"],
        )

        self.key = derive_key_argon2id(
            password=password,
            salt=self.salt,
            time_cost=profile_params["time_cost"],
            memory_cost=profile_params["memory_cost"],
            parallelism=profile_params["parallelism"],
        )

        # Construir header
        self.header_bytes, self.kdf_obj = build_header(kdf_profile, self.salt)

        # Inicializar SecretStream
        self.state = crypto_secretstream_xchacha20poly1305_state()
        self.ss_header = crypto_secretstream_xchacha20poly1305_init_push(
            self.state, self.key
        )

        # Buffer de chunks para gravação atômica
        self.chunks: list[bytes] = []

        # Adicionar header e ss_header
        self.chunks.append(self.header_bytes)
        self.chunks.append(self.ss_header)

        # Lock de escrita
        self._lock_ctx = acquire_lock(self.path, "w")
        self._lock_ctx.__enter__()

        self.finalized = False
        self.entry_count = 0

        logger.info("Container writer inicializado: %s", self.path.name)

    def _push_message(self, data: bytes, tag: int) -> None:
        """Push de mensagem no SecretStream com AAD do header."""
        # AAD = header completo (binding de metadados)
        aad = self.header_bytes

        ciphertext = crypto_secretstream_xchacha20poly1305_push(
            self.state, data, aad, tag
        )

        # Adicionar frame: [len:u32][ciphertext]
        self.chunks.append(_u32_be(len(ciphertext)))
        self.chunks.append(ciphertext)

    def add_manifest(self, manifest: dict[str, Any]) -> None:
        """
        Adiciona manifest como primeira entrada.

        Args:
            manifest: Dicionário com metadados do container

        Raises:
            ValueError: Se já finalizado
        """
        if self.finalized:
            raise ValueError("Container já finalizado")

        entry = ContainerEntry(
            type="manifest",
            id=str(uuid.uuid4()),
            name="__manifest__",
            meta=manifest,
            data=b"",
        )

        self._add_entry(entry)
        logger.debug("Manifest adicionado ao container")

    def add_cg_file(self, *, name: str, data: bytes, meta: dict[str, Any]) -> None:
        """
        Adiciona arquivo do CryptGuard.

        Args:
            name: Nome do arquivo
            data: Conteúdo cifrado (.cg2)
            meta: Metadados (extensão, tags, etc.)

        Raises:
            ValueError: Se já finalizado
        """
        if self.finalized:
            raise ValueError("Container já finalizado")

        entry = ContainerEntry(
            type="cg_file",
            id=str(uuid.uuid4()),
            name=name,
            meta=meta,
            data=data,
        )

        self._add_entry(entry)
        logger.debug("Arquivo CG adicionado: %s (%d bytes)", name, len(data))

    def add_kg_secret(
        self, *, name: str, json_bytes_gz: bytes, meta: dict[str, Any]
    ) -> None:
        """
        Adiciona segredo do KeyGuard.

        Args:
            name: Nome da entrada
            json_bytes_gz: JSON compactado (gzip) da entrada
            meta: Metadados (tags, título, etc.)

        Raises:
            ValueError: Se já finalizado
        """
        if self.finalized:
            raise ValueError("Container já finalizado")

        entry = ContainerEntry(
            type="kg_secret",
            id=str(uuid.uuid4()),
            name=name,
            meta=meta,
            data=json_bytes_gz,
        )

        self._add_entry(entry)
        logger.debug("Segredo KG adicionado: %s (%d bytes)", name, len(json_bytes_gz))

    def _add_entry(self, entry: ContainerEntry) -> None:
        """Adiciona entrada genérica ao stream."""
        # ENTRY_HDR_JSON
        hdr_dict = entry.to_dict()
        hdr_json = _canonical_json(hdr_dict)
        hdr_len = len(hdr_json)

        # ENTRY_DATA
        data_len = len(entry.data)

        # Montar TLV: [HDR_LEN:u32][HDR_JSON][DATA_LEN:u64][DATA]
        tlv = b"".join([
            _u32_be(hdr_len),
            hdr_json,
            _u64_be(data_len),
            entry.data,
        ])

        # Push no stream (TAG_MESSAGE)
        self._push_message(tlv, TAG_MESSAGE)
        self.entry_count += 1

    def finalize(self) -> None:
        """
        Finaliza o container e grava no disco.

        Raises:
            ValueError: Se já finalizado
        """
        if self.finalized:
            raise ValueError("Container já finalizado")

        # Push TAG_FINAL
        final_meta = {
            "entries": self.entry_count,
            "finalized_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        final_json = _canonical_json(final_meta)
        self._push_message(final_json, TAG_FINAL)

        # Gravação atômica
        logger.info("Gravando container: %s (%d entradas)", self.path.name, self.entry_count)
        atomic_save(self.path, iter(self.chunks))

        self.finalized = True

        # Limpar chave da memória (melhor esforço)
        try:
            key_ba = bytearray(self.key)
            for i in range(len(key_ba)):
                key_ba[i] = 0
            del self.key
        except Exception:
            pass

        logger.info("Container criado com sucesso: %s", self.path)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if not self.finalized and exc_type is None:
                self.finalize()
        finally:
            # Liberar lock
            if hasattr(self, "_lock_ctx"):
                try:
                    self._lock_ctx.__exit__(exc_type, exc_val, exc_tb)
                except Exception as e:
                    logger.warning("Erro ao liberar lock: %s", e)


class SecureContainerReader:
    """
    Reader para ler secure containers.

    Uso:
        with SecureContainerReader(path, password) as reader:
            entries = reader.read_all()
            for entry in entries:
                print(entry.name, entry.type)
    """

    def __init__(self, path: Path, password: bytes):
        """
        Inicializa reader.

        Args:
            path: Caminho do arquivo .vault
            password: Senha em bytes

        Raises:
            FileNotFoundError: Arquivo não encontrado
            WrongPasswordError: Senha incorreta
            CorruptContainerError: Container corrompido
        """
        self.path = Path(path)
        self.password = password

        if not self.path.exists():
            raise FileNotFoundError(f"Container não encontrado: {self.path}")

        # Lock de leitura
        self._lock_ctx = acquire_lock(self.path, "r")
        self._lock_ctx.__enter__()

        # Ler arquivo
        with open(self.path, "rb") as f:
            file_data = f.read()

        try:
            # Parse header
            self.kdf_obj, self.salt, header_offset = parse_header(file_data)

            # Derivar chave
            logger.info("Derivando chave do container (Argon2id)")
            self.key = derive_key_argon2id(
                password=password,
                salt=self.salt,
                time_cost=self.kdf_obj["time_cost"],
                memory_cost=self.kdf_obj["memory_cost"],
                parallelism=self.kdf_obj["parallelism"],
            )

            # Ler SS header
            if len(file_data) < header_offset + SS_HEADER_BYTES:
                raise ValueError("Header truncado (SS_HEADER)")

            ss_header = file_data[header_offset : header_offset + SS_HEADER_BYTES]
            stream_offset = header_offset + SS_HEADER_BYTES

            # Inicializar SecretStream para leitura
            self.state = crypto_secretstream_xchacha20poly1305_state()
            crypto_secretstream_xchacha20poly1305_init_pull(
                self.state, ss_header, self.key
            )

            # Header bytes para AAD
            self.header_bytes = file_data[: header_offset]

            # Stream data
            self.stream_data = file_data[stream_offset:]

        except ValueError as e:
            with contextlib.suppress(Exception):
                if hasattr(self, "_lock_ctx"):
                    self._lock_ctx.__exit__(type(e), e, e.__traceback__)
            raise CorruptContainerError(f"Container corrompido: {e}") from e
        except Exception as e:
            with contextlib.suppress(Exception):
                if hasattr(self, "_lock_ctx"):
                    self._lock_ctx.__exit__(type(e), e, e.__traceback__)
            raise WrongPasswordError(
                "Falha na verificação do container. Possíveis causas: "
                "senha incorreta, arquivo corrompido."
            ) from e

        logger.info("Container aberto: %s", self.path.name)

    def _pull_message(self, ciphertext: bytes) -> tuple[bytes, int]:
        """Pull de mensagem do SecretStream."""
        aad = self.header_bytes

        try:
            result = crypto_secretstream_xchacha20poly1305_pull(
                self.state, ciphertext, aad
            )

            # Result pode ser (message, tag) ou (message, ad, tag) dependendo da versão
            if isinstance(result, tuple):
                if len(result) == 2:
                    message, tag = result
                elif len(result) == 3:
                    message, _ad, tag = result
                else:
                    raise ValueError("Formato de resultado inesperado")
            else:
                raise ValueError("Formato de resultado inesperado")

            return message, tag

        except Exception as e:
            raise WrongPasswordError(
                "Falha na verificação do container. Possíveis causas: "
                "senha incorreta, arquivo corrompido."
            ) from e

    def read_all(self) -> list[ContainerEntry]:
        """
        Lê todas as entradas do container.

        Returns:
            Lista de entradas

        Raises:
            WrongPasswordError: Senha incorreta
            CorruptContainerError: Container corrompido
        """
        entries: list[ContainerEntry] = []
        offset = 0

        try:
            while offset < len(self.stream_data):
                # Ler frame: [len:u32][ciphertext]
                if len(self.stream_data) < offset + 4:
                    raise ValueError("Stream truncado (frame length)")

                frame_len = struct.unpack_from(">I", self.stream_data, offset)[0]
                offset += 4

                if len(self.stream_data) < offset + frame_len:
                    raise ValueError("Stream truncado (frame data)")

                ciphertext = self.stream_data[offset : offset + frame_len]
                offset += frame_len

                # Decrypt
                message, tag = self._pull_message(ciphertext)

                # TAG_FINAL?
                if tag == TAG_FINAL:
                    logger.debug("TAG_FINAL encontrado, %d entradas lidas", len(entries))
                    break

                # Parse TLV entry
                entry = self._parse_entry_tlv(message)
                entries.append(entry)

        except ValueError as e:
            raise CorruptContainerError(f"Erro ao ler entradas: {e}") from e

        logger.info("Container lido: %d entradas", len(entries))
        return entries

    def iter_entries(self) -> Iterator[ContainerEntry]:
        """
        Itera sobre entradas do container (para containers grandes).

        Yields:
            ContainerEntry

        Raises:
            WrongPasswordError: Senha incorreta
            CorruptContainerError: Container corrompido
        """
        offset = 0

        try:
            while offset < len(self.stream_data):
                # Ler frame
                if len(self.stream_data) < offset + 4:
                    raise ValueError("Stream truncado (frame length)")

                frame_len = struct.unpack_from(">I", self.stream_data, offset)[0]
                offset += 4

                if len(self.stream_data) < offset + frame_len:
                    raise ValueError("Stream truncado (frame data)")

                ciphertext = self.stream_data[offset : offset + frame_len]
                offset += frame_len

                # Decrypt
                message, tag = self._pull_message(ciphertext)

                # TAG_FINAL?
                if tag == TAG_FINAL:
                    break

                # Parse e yield
                entry = self._parse_entry_tlv(message)
                yield entry

        except ValueError as e:
            raise CorruptContainerError(f"Erro ao iterar entradas: {e}") from e

    def _parse_entry_tlv(self, tlv: bytes) -> ContainerEntry:
        """Parse de entrada TLV."""
        offset = 0

        # HDR_LEN
        if len(tlv) < 4:
            raise ValueError("TLV truncado (HDR_LEN)")
        hdr_len = struct.unpack_from(">I", tlv, offset)[0]
        offset += 4

        # HDR_JSON
        if len(tlv) < offset + hdr_len:
            raise ValueError("TLV truncado (HDR_JSON)")
        hdr_json = tlv[offset : offset + hdr_len]
        offset += hdr_len

        hdr_dict = json.loads(hdr_json.decode("utf-8"))

        # DATA_LEN
        if len(tlv) < offset + 8:
            raise ValueError("TLV truncado (DATA_LEN)")
        data_len = struct.unpack_from(">Q", tlv, offset)[0]
        offset += 8

        # DATA
        if len(tlv) < offset + data_len:
            raise ValueError("TLV truncado (DATA)")
        data = tlv[offset : offset + data_len]

        return ContainerEntry(
            type=hdr_dict["type"],
            id=hdr_dict["id"],
            name=hdr_dict["name"],
            meta=hdr_dict.get("meta", {}),
            data=data,
            created_at=hdr_dict.get("created_at", ""),
            modified_at=hdr_dict.get("modified_at", ""),
        )

    def close(self) -> None:
        """Fecha o reader e libera recursos."""
        # Limpar chave (melhor esforço)
        try:
            key_ba = bytearray(self.key)
            for i in range(len(key_ba)):
                key_ba[i] = 0
            del self.key
        except Exception:
            pass

        logger.debug("Container reader fechado: %s", self.path.name)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.close()
        finally:
            # Liberar lock
            if hasattr(self, "_lock_ctx"):
                try:
                    self._lock_ctx.__exit__(exc_type, exc_val, exc_tb)
                except Exception as e:
                    logger.warning("Erro ao liberar lock: %s", e)


__all__ = [
    "SecureContainerWriter",
    "SecureContainerReader",
    "ContainerEntry",
    "ContainerError",
    "WrongPasswordError",
    "CorruptContainerError",
    "KDF_PROFILES",
]
