"""
Armazenamento atômico e file locking para secure containers.

Fornece primitivas cross-platform para:
- File locking (fcntl/msvcrt)
- Gravação atômica (.tmp + fsync + rename)
- Permissões seguras (POSIX)
"""

from __future__ import annotations

import contextlib
import os
import stat
import tempfile
from pathlib import Path
from typing import Iterator, Literal

from crypto_core.logger import logger

# Platform-specific locking imports
if os.name == "nt":
    import msvcrt
else:
    import fcntl


class LockError(Exception):
    """Erro ao adquirir lock de arquivo."""

    pass


@contextlib.contextmanager
def acquire_lock(
    path: Path, mode: Literal["r", "w"] = "r"
) -> Iterator[None]:
    """
    Context manager para file locking cross-platform.

    Args:
        path: Caminho do arquivo a travar
        mode: 'r' para leitura (compartilhado), 'w' para escrita (exclusivo)

    Raises:
        LockError: Se não conseguir adquirir o lock

    Example:
        with acquire_lock(path, "w"):
            # Gravação exclusiva
            ...
    """
    lock_file = path.with_suffix(path.suffix + ".lock")
    lock_file.parent.mkdir(parents=True, exist_ok=True)

    # Cria arquivo de lock se não existir
    lock_fh = None
    try:
        lock_fh = open(lock_file, "a+b", buffering=0)

        if os.name == "nt":
            # Windows: msvcrt locking
            try:
                if mode == "w":
                    # Exclusive lock
                    msvcrt.locking(lock_fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    # Shared lock (Windows não tem shared lock nativo via msvcrt,
                    # então usamos exclusive mesmo para leitura)
                    msvcrt.locking(lock_fh.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as e:
                raise LockError(
                    f"Não foi possível travar o arquivo {path.name}. "
                    "Ele pode estar em uso por outro processo."
                ) from e
        else:
            # Unix: fcntl locking
            lock_type = fcntl.LOCK_EX if mode == "w" else fcntl.LOCK_SH
            try:
                fcntl.flock(lock_fh.fileno(), lock_type | fcntl.LOCK_NB)
            except OSError as e:
                raise LockError(
                    f"Não foi possível travar o arquivo {path.name}. "
                    "Ele pode estar em uso por outro processo."
                ) from e

        logger.debug("Lock adquirido: %s (mode=%s)", path.name, mode)
        yield

    finally:
        # Release lock
        if lock_fh is not None:
            try:
                if os.name == "nt":
                    try:
                        msvcrt.locking(lock_fh.fileno(), msvcrt.LK_UNLCK, 1)
                    except Exception:
                        pass
                else:
                    fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
                lock_fh.close()
                logger.debug("Lock liberado: %s", path.name)
            except Exception as e:
                logger.warning("Erro ao liberar lock de %s: %s", path.name, e)

        # Limpar arquivo de lock se vazio
        try:
            if lock_file.exists() and lock_file.stat().st_size == 0:
                lock_file.unlink()
        except Exception:
            pass


def atomic_save(path: Path, data_iterable: Iterator[bytes]) -> None:
    """
    Grava dados de forma atômica usando .tmp + fsync + rename.

    Args:
        path: Caminho final do arquivo
        data_iterable: Iterável de chunks de bytes para gravar

    Raises:
        OSError: Erros de I/O

    Segurança:
    - Grava em arquivo temporário no mesmo diretório
    - Faz fsync para garantir persistência
    - Rename atômico para o nome final
    - Define permissões restritivas (POSIX: 0o600)
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    # Criar temp file no mesmo filesystem (para rename atômico)
    tmp_fd, tmp_path_str = tempfile.mkstemp(
        suffix=".tmp", prefix=".cg_", dir=path.parent
    )
    tmp_path = Path(tmp_path_str)

    try:
        # Gravar chunks
        with os.fdopen(tmp_fd, "wb", buffering=0) as f:
            for chunk in data_iterable:
                f.write(chunk)
            f.flush()
            os.fsync(f.fileno())

        # Aplicar permissões seguras antes do rename
        if os.name != "nt":
            try:
                tmp_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600
            except Exception as e:
                logger.warning("Não foi possível definir permissões de %s: %s", tmp_path.name, e)

        # Rename atômico
        tmp_path.replace(path)
        logger.debug("Arquivo salvo atomicamente: %s", path.name)

    except Exception:
        # Cleanup em caso de erro
        try:
            tmp_path.unlink()
        except Exception:
            pass
        raise


def set_secure_permissions(path: Path) -> None:
    """
    Define permissões seguras (0o600) em arquivo existente (POSIX only).

    Args:
        path: Caminho do arquivo
    """
    if os.name == "nt":
        return  # Windows: permissões via ACLs (não implementado aqui)

    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        logger.debug("Permissões seguras aplicadas: %s", path.name)
    except Exception as e:
        logger.warning("Não foi possível definir permissões de %s: %s", path.name, e)


__all__ = ["acquire_lock", "atomic_save", "set_secure_permissions", "LockError"]

