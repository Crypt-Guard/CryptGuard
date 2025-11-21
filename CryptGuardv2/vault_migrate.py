#!/usr/bin/env python3
"""CLI utilitário para migrar vaults do CryptGuard para o novo formato.

O novo formato embute o salt no arquivo principal e elimina o sidecar
``.salt``. Este script cria backups automáticos e regrava o arquivo no
formato atualizado usando o backend do projeto.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
import shutil

from vault import AtomicStorageBackend, VaultManager


def _copy_backup(src: Path, label: str) -> Path | None:
    if not src.exists():
        return None
    backup = src.with_suffix(src.suffix + ".bak")
    try:
        shutil.copy2(src, backup)
    except Exception as exc:  # pragma: no cover - IO errors only at runtime
        print(f"[WARN] Falha ao criar backup de {label}: {exc}", file=sys.stderr)
    else:
        print(f"[INFO] Backup de {label} criado em {backup}")
    return backup


def migrate(src: Path, dst: Path, password: str, overwrite: bool) -> None:
    src = src.resolve()
    dst = dst.resolve()

    if not src.exists():
        raise FileNotFoundError(f"Arquivo de entrada inexistente: {src}")

    if dst.exists() and not overwrite:
        raise FileExistsError(
            f"Arquivo de destino {dst} já existe. Use --overwrite para substituí-lo."
        )

    manager = VaultManager(path=src)
    manager.open(password)

    print(f"[INFO] Formato detectado: {manager._format}")
    if manager._format == "embedded" and src == dst:
        print("[INFO] Vault já está no novo formato; nenhuma alteração necessária.")
        return

    # Backups do arquivo e do salt legado (se existir)
    _copy_backup(src, "vault")
    salt_sidecar = src.with_suffix(src.suffix + ".salt")
    _copy_backup(salt_sidecar, "salt")

    if dst != src:
        dst.parent.mkdir(parents=True, exist_ok=True)
        manager.path = dst
        manager._storage = AtomicStorageBackend(dst)
        manager.salt_path = dst.with_suffix(dst.suffix + ".salt")

    manager._format = manager._format or "embedded"
    manager._save()
    manager.close()
    print(f"[INFO] Vault salvo no novo formato em {manager.path}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Migrar CryptGuard Vault legado para novo formato")
    parser.add_argument("--in", dest="src", required=True, help="Arquivo .kgv legado")
    parser.add_argument("--out", dest="dst", required=True, help="Arquivo destino no novo formato")
    parser.add_argument(
        "--password",
        dest="password",
        help="Senha do vault. Se omitida, será solicitada via prompt seguro.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Permite sobrescrever o arquivo de destino se ele já existir.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    src = Path(args.src).expanduser()
    dst = Path(args.dst).expanduser()
    password = args.password or getpass.getpass("Senha do Vault: ")

    try:
        migrate(src, dst, password, overwrite=args.overwrite)
    except Exception as exc:
        print(f"[ERRO] {exc}", file=sys.stderr)
        return 1
    finally:
        password = ""  # evita manter a senha em memória
    return 0


if __name__ == "__main__":  # pragma: no cover - executável direto
    raise SystemExit(main())

