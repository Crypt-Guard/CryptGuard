#!/usr/bin/env python3
"""
CLI para Secure Containers do CryptGuardv2.

Comandos:
  cryptguard container create --out FILE.vault [OPTIONS]
  cryptguard container read --in FILE.vault [OPTIONS]
  cryptguard container list --in FILE.vault
  cryptguard container extract --in FILE.vault --to DIR [OPTIONS]
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from containers.secure_container import (
    ContainerEntry,
    CorruptContainerError,
    SecureContainerReader,
    SecureContainerWriter,
    WrongPasswordError,
)
from crypto_core.logger import logger
from integration.container_bridge import (
    collect_from_cryptguard,
    collect_from_keyguard,
    integrate_into_cryptguard,
    integrate_into_keyguard,
)


def prompt_password(prompt: str = "Senha do container: ") -> bytes:
    """Solicita senha do usuário de forma segura."""
    try:
        password = getpass.getpass(prompt)
        return password.encode("utf-8")
    except KeyboardInterrupt:
        print("\n\nOperação cancelada.")
        sys.exit(1)


def cmd_create(args: argparse.Namespace) -> int:
    """Comando: criar container."""
    output_path = Path(args.out)

    if output_path.exists() and not args.force:
        print(f"Erro: {output_path} já existe. Use --force para sobrescrever.")
        return 1

    # Solicitar senha
    password = prompt_password("Digite a senha do container: ")
    password_confirm = prompt_password("Confirme a senha: ")

    if password != password_confirm:
        print("Erro: As senhas não coincidem.")
        return 1

    # Coletar itens
    cg_items = []
    kg_entries = []

    # TODO: Implementar coleta de itens via CLI
    # Por ora, criar container vazio para demonstração

    try:
        with SecureContainerWriter(output_path, password, args.kdf_profile) as writer:
            # Manifest
            manifest = {
                "created_at": "CLI",
                "cg_count": len(cg_items),
                "kg_count": len(kg_entries),
                "version": 1,
            }
            writer.add_manifest(manifest)

            # Adicionar itens (placeholder)
            # Em implementação completa, coletar de vaults especificados

            writer.finalize()

        print(f"Container criado: {output_path}")
        return 0

    except Exception as e:
        logger.error("Erro ao criar container: %s", e)
        print(f"Erro: {e}")
        return 1


def cmd_list(args: argparse.Namespace) -> int:
    """Comando: listar conteúdo do container."""
    container_path = Path(args.input)

    if not container_path.exists():
        print(f"Erro: Container não encontrado: {container_path}")
        return 1

    # Solicitar senha
    password = prompt_password()

    try:
        with SecureContainerReader(container_path, password) as reader:
            entries = reader.read_all()

        # Filtrar manifest
        entries = [e for e in entries if e.type != "manifest"]

        # Exibir
        print(f"\nContainer: {container_path}")
        print(f"Total de entradas: {len(entries)}\n")

        print(f"{'Tipo':<12} {'Nome':<40} {'Tamanho':<12} {'Criado'}")
        print("-" * 90)

        for entry in entries:
            type_text = "Arquivo" if entry.type == "cg_file" else "Segredo"
            size_text = f"{len(entry.data)} B" if entry.type == "cg_file" else "-"
            created = entry.created_at[:10]

            print(f"{type_text:<12} {entry.name[:40]:<40} {size_text:<12} {created}")

        return 0

    except WrongPasswordError:
        print("Erro: Senha incorreta ou container corrompido.")
        return 1

    except CorruptContainerError as e:
        print(f"Erro: Container corrompido: {e}")
        return 1

    except Exception as e:
        logger.error("Erro ao ler container: %s", e)
        print(f"Erro: {e}")
        return 1


def cmd_extract(args: argparse.Namespace) -> int:
    """Comando: extrair arquivos do container."""
    container_path = Path(args.input)
    extract_dir = Path(args.to)

    if not container_path.exists():
        print(f"Erro: Container não encontrado: {container_path}")
        return 1

    extract_dir.mkdir(parents=True, exist_ok=True)

    # Solicitar senha
    password = prompt_password()

    try:
        with SecureContainerReader(container_path, password) as reader:
            entries = reader.read_all()

        # Filtrar apenas cg_file
        cg_files = [e for e in entries if e.type == "cg_file"]

        if not cg_files:
            print("Aviso: Nenhum arquivo encontrado no container.")
            return 0

        print(f"\nExtraindo {len(cg_files)} arquivo(s) para: {extract_dir}")

        success_count = 0

        for entry in cg_files:
            try:
                # Nome do arquivo
                orig_name = entry.meta.get("orig_name", entry.name)
                extension = entry.meta.get("extension", ".cg2")

                if not extension.endswith(".cg2"):
                    extension = ".cg2"

                file_name = f"{orig_name}{extension}" if not orig_name.endswith(extension) else orig_name

                # Anti path traversal
                safe_name = Path(file_name).name
                if not safe_name or safe_name in (".", ".."):
                    safe_name = f"extracted_{entry.id}.cg2"

                file_path = extract_dir / safe_name

                # Evitar sobrescrever
                if file_path.exists() and not args.force:
                    stem = file_path.stem
                    suffix = file_path.suffix
                    counter = 1
                    while file_path.exists():
                        file_path = extract_dir / f"{stem}({counter}){suffix}"
                        counter += 1

                # Gravar
                file_path.write_bytes(entry.data)
                success_count += 1
                print(f"  ✓ {file_path.name}")

            except Exception as e:
                print(f"  ✗ Erro em {entry.name}: {e}")

        print(f"\nExtração concluída: {success_count}/{len(cg_files)} arquivos.")
        return 0

    except WrongPasswordError:
        print("Erro: Senha incorreta ou container corrompido.")
        return 1

    except CorruptContainerError as e:
        print(f"Erro: Container corrompido: {e}")
        return 1

    except Exception as e:
        logger.error("Erro ao extrair: %s", e)
        print(f"Erro: {e}")
        return 1


def cmd_integrate(args: argparse.Namespace) -> int:
    """Comando: integrar itens do container nos vaults."""
    container_path = Path(args.input)

    if not container_path.exists():
        print(f"Erro: Container não encontrado: {container_path}")
        return 1

    # Solicitar senha
    password = prompt_password()

    try:
        with SecureContainerReader(container_path, password) as reader:
            entries = reader.read_all()

        # Filtrar por tipo
        cg_entries = [e for e in entries if e.type == "cg_file"]
        kg_entries = [e for e in entries if e.type == "kg_secret"]

        # Integrar CryptGuard
        if cg_entries and args.target in ("cryptguard", "all"):
            vault_dir = Path(args.cg_vault_dir or Path.home() / "CryptGuard" / "vault")
            vault_dir.mkdir(parents=True, exist_ok=True)

            print(f"\nIntegrando {len(cg_entries)} arquivo(s) no CryptGuard...")
            report = integrate_into_cryptguard(cg_entries, vault_dir, args.conflict_mode)

            print(f"  Total: {report.total}")
            print(f"  Integrados: {report.integrated}")
            print(f"  Pulados: {report.skipped}")
            print(f"  Duplicados: {report.duplicated}")

            if report.errors:
                print(f"  Erros: {len(report.errors)}")
                for err in report.errors[:5]:
                    print(f"    • {err}")

        # Integrar KeyGuard
        if kg_entries and args.target in ("keyguard", "all"):
            print("\nAviso: Integração KeyGuard via CLI não implementada.")
            print("Use a interface gráfica para integrar entradas de senhas.")

        return 0

    except WrongPasswordError:
        print("Erro: Senha incorreta ou container corrompido.")
        return 1

    except CorruptContainerError as e:
        print(f"Erro: Container corrompido: {e}")
        return 1

    except Exception as e:
        logger.error("Erro ao integrar: %s", e)
        print(f"Erro: {e}")
        return 1


def main(argv: list[str] | None = None) -> int:
    """Ponto de entrada principal da CLI."""
    parser = argparse.ArgumentParser(
        prog="cryptguard container",
        description="Gerenciamento de Secure Containers do CryptGuardv2",
    )

    subparsers = parser.add_subparsers(dest="command", help="Comando")

    # Comando: create
    parser_create = subparsers.add_parser("create", help="Criar novo container")
    parser_create.add_argument("--out", required=True, help="Caminho do container (.vault)")
    parser_create.add_argument("--kdf-profile", choices=["moderate", "strong"], default="moderate", help="Perfil KDF")
    parser_create.add_argument("--force", action="store_true", help="Sobrescrever se existir")

    # Comando: list
    parser_list = subparsers.add_parser("list", help="Listar conteúdo do container")
    parser_list.add_argument("--in", dest="input", required=True, help="Caminho do container")

    # Comando: extract
    parser_extract = subparsers.add_parser("extract", help="Extrair arquivos do container")
    parser_extract.add_argument("--in", dest="input", required=True, help="Caminho do container")
    parser_extract.add_argument("--to", required=True, help="Diretório de destino")
    parser_extract.add_argument("--force", action="store_true", help="Sobrescrever arquivos existentes")

    # Comando: integrate
    parser_integrate = subparsers.add_parser("integrate", help="Integrar itens nos vaults")
    parser_integrate.add_argument("--in", dest="input", required=True, help="Caminho do container")
    parser_integrate.add_argument("--target", choices=["cryptguard", "keyguard", "all"], default="all", help="Vault alvo")
    parser_integrate.add_argument("--conflict-mode", choices=["skip", "duplicate", "replace"], default="skip", help="Modo de conflito")
    parser_integrate.add_argument("--cg-vault-dir", help="Diretório do vault CryptGuard")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    # Despachar comando
    if args.command == "create":
        return cmd_create(args)
    elif args.command == "list":
        return cmd_list(args)
    elif args.command == "extract":
        return cmd_extract(args)
    elif args.command == "integrate":
        return cmd_integrate(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())

