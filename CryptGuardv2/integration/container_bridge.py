"""
Bridge de integração entre containers e vaults.

Funções para:
- Coletar itens dos vaults do CryptGuard e KeyGuard
- Integrar itens de containers nos vaults
- Tratar conflitos de nome/ID
"""

from __future__ import annotations

import gzip
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from crypto_core.logger import logger

from containers.secure_container import ContainerEntry


@dataclass
class IntegrateReport:
    """Relatório de integração de itens."""

    total: int = 0
    integrated: int = 0
    skipped: int = 0
    duplicated: int = 0
    errors: list[str] = field(default_factory=list)

    def add_success(self) -> None:
        """Marca um item como integrado com sucesso."""
        self.integrated += 1

    def add_skip(self, reason: str = "") -> None:
        """Marca um item como pulado."""
        self.skipped += 1
        if reason:
            self.errors.append(f"Pulado: {reason}")

    def add_duplicate(self) -> None:
        """Marca um item como duplicado."""
        self.duplicated += 1

    def add_error(self, msg: str) -> None:
        """Adiciona erro ao relatório."""
        self.errors.append(msg)

    def to_dict(self) -> dict[str, Any]:
        """Converte para dicionário."""
        return {
            "total": self.total,
            "integrated": self.integrated,
            "skipped": self.skipped,
            "duplicated": self.duplicated,
            "errors": self.errors,
        }


# ============================================================================
# CryptGuard Vault (arquivos .cg2)
# ============================================================================


def collect_from_cryptguard(
    vault_items: list[dict[str, Any]], vault_dir: Path
) -> list[ContainerEntry]:
    """
    Coleta itens selecionados do Vault do CryptGuard.

    Args:
        vault_items: Lista de dicts com {path, name, size, data, ...}
        vault_dir: Diretório do vault (pode ser None)

    Returns:
        Lista de ContainerEntry prontas para adicionar ao container

    O conteúdo já vem cifrado no campo 'data' do item.
    O container adiciona outra camada de criptografia (defesa em profundidade).
    """
    entries: list[ContainerEntry] = []

    for item in vault_items:
        try:
            # Extrair dados cifrados (já incluídos no item)
            cg2_data = item.get("data")
            
            if cg2_data is None:
                # Fallback: tentar ler de arquivo se 'data' não estiver presente
                item_path = Path(item.get("path", ""))
                if vault_dir and not item_path.is_absolute():
                    item_path = vault_dir / item_path

                if item_path.exists():
                    cg2_data = item_path.read_bytes()
                else:
                    logger.warning("Item sem dados e arquivo não encontrado: %s", item.get("name", "?"))
                    continue
            
            if not isinstance(cg2_data, bytes):
                cg2_data = bytes(cg2_data)

            # Metadados
            meta = {
                "orig_size": len(cg2_data),
                "vault_type": "cryptguard",
            }

            # Incluir extensão se disponível
            if "extension" in item:
                meta["extension"] = item["extension"]

            # Incluir nome original se disponível
            if "orig_name" in item:
                meta["orig_name"] = item["orig_name"]

            # Nome de exibição
            display_name = item.get("name", item.get("id", "unnamed"))

            entry = ContainerEntry(
                type="cg_file",
                id=item.get("id", display_name),
                name=display_name,
                meta=meta,
                data=cg2_data,
                created_at=item.get("created_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
                modified_at=item.get("modified_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
            )

            entries.append(entry)
            logger.debug("Item CryptGuard coletado: %s (%d bytes)", display_name, len(cg2_data))

        except Exception as e:
            logger.warning("Erro ao coletar item do CryptGuard: %s", e)
            continue

    logger.info("Coletados %d itens do CryptGuard", len(entries))
    return entries


def integrate_into_cryptguard(
    entries: list[ContainerEntry],
    vault_dir: Path,
    conflict_mode: Literal["skip", "duplicate", "replace"] = "skip",
) -> IntegrateReport:
    """
    Integra itens de container no Vault do CryptGuard.

    Args:
        entries: Lista de ContainerEntry do tipo 'cg_file'
        vault_dir: Diretório do vault CryptGuard
        conflict_mode: Como tratar conflitos de nome
            - 'skip': Pular itens existentes
            - 'duplicate': Criar duplicata com sufixo
            - 'replace': Substituir item existente

    Returns:
        IntegrateReport com estatísticas

    Os arquivos .cg2 são salvos diretamente no diretório do vault.
    """
    report = IntegrateReport()
    vault_dir.mkdir(parents=True, exist_ok=True)

    for entry in entries:
        report.total += 1

        if entry.type != "cg_file":
            report.add_skip(f"Tipo não suportado: {entry.type}")
            continue

        try:
            # Determinar nome do arquivo
            orig_name = entry.meta.get("orig_name", entry.name)
            extension = entry.meta.get("extension", ".cg2")

            # Garantir extensão .cg2
            if not extension.endswith(".cg2"):
                extension = ".cg2"

            # Construir caminho
            file_name = f"{orig_name}{extension}" if not orig_name.endswith(extension) else orig_name
            file_path = vault_dir / file_name

            # Tratar conflitos
            if file_path.exists():
                if conflict_mode == "skip":
                    report.add_skip(f"Arquivo já existe: {file_name}")
                    continue
                elif conflict_mode == "duplicate":
                    # Criar nome com sufixo
                    stem = file_path.stem
                    suffix = file_path.suffix
                    counter = 1
                    while file_path.exists():
                        file_path = vault_dir / f"{stem}({counter}){suffix}"
                        counter += 1
                    report.add_duplicate()
                elif conflict_mode == "replace":
                    # Substituir (fazer backup?)
                    backup_path = file_path.with_suffix(file_path.suffix + ".bak")
                    if file_path.exists():
                        file_path.replace(backup_path)
                        logger.debug("Backup criado: %s", backup_path.name)

            # Gravar arquivo
            file_path.write_bytes(entry.data)
            report.add_success()

            logger.info("Item integrado no CryptGuard: %s", file_path.name)

        except Exception as e:
            logger.error("Erro ao integrar item no CryptGuard: %s", e)
            report.add_error(f"Erro em {entry.name}: {e}")

    logger.info(
        "Integração CryptGuard: %d/%d itens (pulados=%d, duplicados=%d, erros=%d)",
        report.integrated,
        report.total,
        report.skipped,
        report.duplicated,
        len(report.errors),
    )

    return report


# ============================================================================
# KeyGuard Vault (senhas/entradas)
# ============================================================================


def collect_from_keyguard(
    vault_entries: list[dict[str, Any]]
) -> list[ContainerEntry]:
    """
    Coleta entradas selecionadas do Vault do KeyGuard.

    Args:
        vault_entries: Lista de dicts com entradas do vault
            Exemplo: {"name": "GitHub", "password_b64": "...", "metadata": {...}}

    Returns:
        Lista de ContainerEntry com JSON compactado (gzip)

    Cada entrada é serializada como JSON e compactada com gzip antes
    de ser adicionada ao container.
    """
    entries: list[ContainerEntry] = []

    for vault_entry in vault_entries:
        try:
            # Serializar entrada como JSON
            entry_json = json.dumps(
                vault_entry, sort_keys=True, ensure_ascii=False
            ).encode("utf-8")

            # Compactar com gzip
            json_gz = gzip.compress(entry_json, compresslevel=6)

            # Metadados
            meta = {
                "tags": vault_entry.get("metadata", {}).get("tags", []),
                "vault_type": "keyguard",
            }

            # Nome de exibição
            display_name = vault_entry.get("name", "Unnamed")

            entry = ContainerEntry(
                type="kg_secret",
                id=vault_entry.get("id", display_name),
                name=display_name,
                meta=meta,
                data=json_gz,
                created_at=vault_entry.get("created", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
                modified_at=vault_entry.get("modified", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
            )

            entries.append(entry)
            logger.debug("Entrada KeyGuard coletada: %s", display_name)

        except Exception as e:
            logger.warning("Erro ao coletar entrada do KeyGuard: %s", e)
            continue

    logger.info("Coletadas %d entradas do KeyGuard", len(entries))
    return entries


def integrate_into_keyguard(
    entries: list[ContainerEntry],
    vault_manager,
    conflict_mode: Literal["skip", "duplicate", "replace"] = "skip",
) -> IntegrateReport:
    """
    Integra entradas de container no Vault do KeyGuard.

    Args:
        entries: Lista de ContainerEntry do tipo 'kg_secret'
        vault_manager: Instância de VaultManager (KeyGuard)
        conflict_mode: Como tratar conflitos de nome
            - 'skip': Pular entradas existentes
            - 'duplicate': Criar duplicata com sufixo
            - 'replace': Substituir entrada existente

    Returns:
        IntegrateReport com estatísticas

    As entradas são descompactadas (gunzip) e adicionadas ao vault.
    """
    report = IntegrateReport()

    # Obter entradas existentes (para detectar conflitos)
    # vault_manager.entries é um dict[str, VaultEntry]
    existing_names = set(vault_manager.entries.keys())

    for entry in entries:
        report.total += 1

        if entry.type != "kg_secret":
            report.add_skip(f"Tipo não suportado: {entry.type}")
            continue

        try:
            # Descompactar JSON
            json_bytes = gzip.decompress(entry.data)
            vault_entry_dict = json.loads(json_bytes.decode("utf-8"))

            # Nome da entrada
            entry_name = vault_entry_dict.get("name", entry.name)

            # Tratar conflitos
            final_name = entry_name
            if entry_name in existing_names:
                if conflict_mode == "skip":
                    report.add_skip(f"Entrada já existe: {entry_name}")
                    continue
                elif conflict_mode == "duplicate":
                    # Criar nome com sufixo
                    counter = 1
                    while f"{entry_name}({counter})" in existing_names:
                        counter += 1
                    final_name = f"{entry_name}({counter})"
                    vault_entry_dict["name"] = final_name
                    existing_names.add(final_name)
                    report.add_duplicate()
                elif conflict_mode == "replace":
                    # Remover entrada existente do dicionário
                    if entry_name in vault_manager.entries:
                        del vault_manager.entries[entry_name]
                    if entry_name in vault_manager.entry_order:
                        vault_manager.entry_order.remove(entry_name)
                    existing_names.discard(entry_name)

            # Criar VaultEntry
            from modules.keyguard.vault_backend import VaultEntry

            new_entry = VaultEntry(
                name=final_name,
                password_b64=vault_entry_dict.get("password_b64", ""),
                metadata=vault_entry_dict.get("metadata", {}),
                created=vault_entry_dict.get("created", time.time()),
                modified=time.time(),
            )

            # Adicionar ao vault (dict + ordem)
            vault_manager.entries[final_name] = new_entry
            if final_name not in vault_manager.entry_order:
                vault_manager.entry_order.append(final_name)
            existing_names.add(final_name)
            report.add_success()

            logger.info("Entrada integrada no KeyGuard: %s", final_name)

        except Exception as e:
            logger.error("Erro ao integrar entrada no KeyGuard: %s", e)
            report.add_error(f"Erro em {entry.name}: {e}")

    # Salvar vault usando autosave
    try:
        if hasattr(vault_manager, '_autosave'):
            vault_manager._autosave()
        elif hasattr(vault_manager, 'save'):
            vault_manager.save()
        else:
            vault_manager._save()
        logger.info("Vault KeyGuard salvo com sucesso")
    except Exception as e:
        logger.error("Erro ao salvar vault KeyGuard: %s", e)
        report.add_error(f"Erro ao salvar vault: {e}")

    logger.info(
        "Integração KeyGuard: %d/%d entradas (pulados=%d, duplicados=%d, erros=%d)",
        report.integrated,
        report.total,
        report.skipped,
        report.duplicated,
        len(report.errors),
    )

    return report


__all__ = [
    "collect_from_cryptguard",
    "collect_from_keyguard",
    "integrate_into_cryptguard",
    "integrate_into_keyguard",
    "IntegrateReport",
]

