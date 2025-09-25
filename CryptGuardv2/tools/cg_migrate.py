#!/usr/bin/env python3
"""
CLI de migração para padronizar headers de 64B para 256B em arquivos CG2.

Uso:
    python -m tools.cg_migrate --help
    python -m tools.cg_migrate --dry-run /caminho/para/arquivo.cg2
    python -m tools.cg_migrate --in-place /caminho/para/arquivo.cg2
    python -m tools.cg_migrate --backup /caminho/para/arquivo.cg2

Exit codes:
    0: Sucesso
    1: Erro de argumentos
    2: Arquivo não encontrado ou ilegível
    3: Header inválido (não é CG2)
    4: Erro de migração
    5: Erro de escrita
"""

import argparse
import logging
import shutil
import sys
from pathlib import Path

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class CG2Migrator:
    """Migrador de arquivos CG2 para header de 256B."""

    def __init__(self, backup: bool = True):
        self.backup = backup
        self.stats = {"processed": 0, "migrated": 0, "skipped": 0, "errors": 0}

    def detect_header_size(self, data: bytes) -> tuple[int, dict]:
        """
        Detecta tamanho do header (64B ou 256B) e retorna parâmetros.

        Returns:
            Tuple[tamanho_header, parâmetros_parseados]
        """
        from crypto_core.format import HEADER_SIZE, LEGACY_HEADER_SIZE, _parse_header_json

        # Tenta 256B primeiro (padrão atual)
        if len(data) >= HEADER_SIZE:
            try:
                return HEADER_SIZE, _parse_header_json(data[:HEADER_SIZE])
            except Exception:
                pass

        # Tenta 64B (legado)
        if len(data) >= LEGACY_HEADER_SIZE:
            try:
                return LEGACY_HEADER_SIZE, _parse_header_json(data[:LEGACY_HEADER_SIZE])
            except Exception:
                pass

        raise ValueError("Header inválido ou arquivo não é CG2")

    def needs_migration(self, file_path: Path) -> bool:
        """Verifica se arquivo precisa de migração (header de 64B)."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            header_size, _ = self.detect_header_size(data)
            return header_size == 64  # Precisa migrar se for 64B

        except Exception:
            return False

    def migrate_file(self, file_path: Path, dry_run: bool = True) -> bool:
        """
        Migra arquivo de 64B para 256B header.

        Args:
            file_path: Caminho do arquivo a migrar
            dry_run: Se True, apenas simula (não escreve)

        Returns:
            True se migração bem-sucedida
        """
        try:
            # Backup se necessário
            if self.backup and not dry_run:
                backup_path = file_path.with_suffix(file_path.suffix + ".backup")
                shutil.copy2(file_path, backup_path)
                logger.info(f"Backup criado: {backup_path}")

            # Lê arquivo
            with open(file_path, "rb") as f:
                data = f.read()

            # Detecta header atual
            current_header_size, params = self.detect_header_size(data)

            if current_header_size == 256:
                logger.info(f"Arquivo já tem header de 256B: {file_path}")
                self.stats["skipped"] += 1
                return True

            logger.info(f"Migrando {file_path} (64B → 256B)")

            # Serializa novo header de 256B
            from crypto_core.format import serialize_header

            new_header = serialize_header(params)

            # Verifica se AAD será consistente
            from crypto_core.format import get_aad_for_header

            old_aad = get_aad_for_header(data[:current_header_size])
            new_aad = get_aad_for_header(new_header)

            if old_aad != new_aad.rstrip(b"\x00"):
                logger.warning("AAD será diferente após migração - descriptografia pode falhar!")
                logger.warning(f"AAD antigo: {old_aad.hex()}")
                logger.warning(f"AAD novo: {new_aad.rstrip(b'\x00').hex()}")

            # Monta novo arquivo
            new_data = new_header + data[current_header_size:]

            if dry_run:
                logger.info(f"DRY-RUN: Seria escrito {len(new_data)} bytes (era {len(data)})")
                self.stats["migrated"] += 1
                return True

            # Escreve arquivo migrado
            with open(file_path, "wb") as f:
                f.write(new_data)

            logger.info(f"Migração concluída: {file_path} ({len(data)} → {len(new_data)} bytes)")
            self.stats["migrated"] += 1
            return True

        except Exception as e:
            logger.error(f"Erro migrando {file_path}: {e}")
            self.stats["errors"] += 1
            return False

    def migrate_directory(
        self, dir_path: Path, dry_run: bool = True, recursive: bool = False
    ) -> dict:
        """
        Migra todos os arquivos CG2 em um diretório.

        Args:
            dir_path: Diretório a processar
            dry_run: Se True, apenas simula
            recursive: Se True, processa subdiretórios

        Returns:
            Dicionário com estatísticas
        """
        if not dir_path.exists():
            raise FileNotFoundError(f"Diretório não encontrado: {dir_path}")

        logger.info(f"Processando diretório: {dir_path} (dry_run={dry_run}, recursive={recursive})")

        pattern = "**/*.cg2" if recursive else "*.cg2"

        for file_path in dir_path.glob(pattern):
            if file_path.is_file():
                self.migrate_file(file_path, dry_run)
                self.stats["processed"] += 1

        return dict(self.stats)

    def print_stats(self):
        """Imprime estatísticas da migração."""
        print("\n=== ESTATÍSTICAS DA MIGRAÇÃO ===")
        print(f"Arquivos processados: {self.stats['processed']}")
        print(f"Arquivos migrados: {self.stats['migrated']}")
        print(f"Arquivos pulados: {self.stats['skipped']}")
        print(f"Erros: {self.stats['errors']}")


def main():
    """CLI principal."""
    parser = argparse.ArgumentParser(
        description="Migração de headers CG2 de 64B para 256B",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
    cg-migrate --dry-run arquivo.cg2          # Simula migração
    cg-migrate --in-place arquivo.cg2         # Migra arquivo
    cg-migrate --backup arquivo.cg2           # Migra com backup
    cg-migrate --dry-run /pasta/              # Simula migração de pasta
    cg-migrate --in-place /pasta/ --recursive # Migra pasta recursivamente
        """,
    )

    parser.add_argument("path", help="Arquivo ou diretório a processar")

    parser.add_argument(
        "--dry-run", action="store_true", default=True, help="Apenas simula migração (padrão)"
    )

    parser.add_argument(
        "--in-place", action="store_true", help="Migra arquivos no local (sobrescreve)"
    )

    parser.add_argument("--backup", action="store_true", help="Cria backups antes de migrar")

    parser.add_argument(
        "--recursive", action="store_true", help="Processa diretórios recursivamente"
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Modo verboso (mais logs)")

    args = parser.parse_args()

    # Configura logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Valida argumentos
    path = Path(args.path)

    if args.in_place and args.backup:
        # --in-place com --backup é redundante mas permitido
        pass
    elif args.in_place:
        # --in-place implica --backup=False
        args.backup = False
    elif args.backup and not args.in_place:
        # --backup sem --in-place não faz sentido
        logger.error("--backup só pode ser usado com --in-place")
        sys.exit(1)

    # Cria migrador
    migrator = CG2Migrator(backup=args.backup)

    try:
        if path.is_file():
            # Arquivo único
            if migrator.migrate_file(path, args.dry_run):
                migrator.print_stats()
                sys.exit(0)
            else:
                sys.exit(4)

        elif path.is_dir():
            # Diretório
            stats = migrator.migrate_directory(path, args.dry_run, args.recursive)
            migrator.print_stats()

            if stats["errors"] > 0:
                sys.exit(4)
            else:
                sys.exit(0)

        else:
            logger.error(f"Caminho não encontrado: {path}")
            sys.exit(2)

    except KeyboardInterrupt:
        logger.info("Migração interrompida pelo usuário")
        migrator.print_stats()
        sys.exit(1)
    except Exception as e:
        logger.error(f"Erro crítico: {e}")
        sys.exit(5)


if __name__ == "__main__":
    main()
