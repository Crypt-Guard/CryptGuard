"""
Operações de I/O seguras: escrita atômica e permissões seguras

Fornece funções para escrita atômica de arquivos e criação segura
de diretórios, com tratamento adequado de diferentes sistemas operacionais.
"""

import os
import tempfile
from pathlib import Path

# Permissões padrão seguras
DEFAULT_FILE_MODE = 0o600  # -rw-------
DEFAULT_DIR_MODE = 0o700  # drwx------
DEFAULT_UMASK = 0o077  # Máscara para bloquear outros


def secure_mkdir(path: str | Path, mode: int = DEFAULT_DIR_MODE) -> Path:
    """
    Cria diretório com permissões seguras.

    Args:
        path: Caminho do diretório a criar
        mode: Modo de permissão (Unix)

    Returns:
        Path do diretório criado

    Raises:
        OSError: Se criação falha
    """
    path = Path(path)

    # Cria diretório e pais se necessário
    path.mkdir(parents=True, exist_ok=True)

    # Tenta definir permissões (funciona em Unix)
    # No Windows, chmod pode não funcionar - apenas continua
    import contextlib

    with contextlib.suppress(OSError):
        os.chmod(path, mode)

    return path


def atomic_write_bytes(path: str | Path, data: bytes, mode: int = DEFAULT_FILE_MODE) -> None:
    """
    Escreve dados em arquivo de forma atômica e segura.

    Usa NamedTemporaryFile + os.replace para garantir atomicidade.

    Args:
        path: Caminho do arquivo de destino
        data: Dados a escrever
        mode: Modo de permissão do arquivo (Unix)

    Raises:
        OSError: Se escrita falha
        ValueError: Se dados inválidos
    """
    if not data:
        raise ValueError("Dados não podem ser vazios")

    path = Path(path)

    # Cria diretório pai se necessário
    if path.parent.exists():
        secure_mkdir(path.parent)

    # Usa NamedTemporaryFile para escrita atômica
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=path.parent, delete=False, suffix=".tmp"
    ) as tmp_file:
        # Escreve dados
        tmp_file.write(data)
        tmp_file.flush()

        # Força sincronização (importante para atomicidade)
        # fsync pode não estar disponível em todos os sistemas
        import contextlib

        with contextlib.suppress(OSError, AttributeError):
            os.fsync(tmp_file.fileno())

        tmp_path = Path(tmp_file.name)

    # Move atomicamente para destino
    try:
        os.replace(tmp_path, path)

        # Define permissões (funciona em Unix)
        # No Windows, chmod pode não funcionar
        import contextlib

        with contextlib.suppress(OSError):
            os.chmod(path, mode)

    except OSError:
        # Limpa arquivo temporário em caso de erro
        import contextlib

        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise


def atomic_write_text(
    path: str | Path, text: str, mode: int = DEFAULT_FILE_MODE, encoding: str = "utf-8"
) -> None:
    """
    Escreve texto em arquivo de forma atômica.

    Args:
        path: Caminho do arquivo
        text: Texto a escrever
        mode: Modo de permissão
        encoding: Encoding do texto
    """
    data = text.encode(encoding)
    atomic_write_bytes(path, data, mode)


def safe_read_bytes(path: str | Path) -> bytes:
    """
    Lê bytes de arquivo com verificações básicas.

    Args:
        path: Caminho do arquivo

    Returns:
        Bytes lidos

    Raises:
        FileNotFoundError: Se arquivo não existe
        OSError: Se leitura falha
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Arquivo não encontrado: {path}")

    if not path.is_file():
        raise OSError(f"Não é um arquivo: {path}")

    return path.read_bytes()


def safe_read_text(path: str | Path, encoding: str = "utf-8") -> str:
    """
    Lê texto de arquivo com verificações.

    Args:
        path: Caminho do arquivo
        encoding: Encoding do texto

    Returns:
        Texto lido
    """
    data = safe_read_bytes(path)
    return data.decode(encoding)


def is_safe_path(base_path: str | Path, target_path: str | Path) -> bool:
    """
    Verifica se target_path está dentro de base_path (prevenção de path traversal).

    Args:
        base_path: Diretório base permitido
        target_path: Caminho a verificar

    Returns:
        True se seguro
    """
    base_path = Path(base_path).resolve()
    target_path = Path(target_path).resolve()

    try:
        # Verifica se target está dentro de base
        target_path.relative_to(base_path)
        return True
    except ValueError:
        return False


class AtomicFileWriter:
    """
    Context manager para escrita atômica de arquivos.

    Exemplo:
        with AtomicFileWriter("file.txt") as f:
            f.write(b"data")
    """

    def __init__(self, path: str | Path, mode: int = DEFAULT_FILE_MODE):
        self.path = Path(path)
        self.mode = mode
        self.tmp_file = None
        self.closed = False

    def __enter__(self):
        if self.path.parent.exists():
            secure_mkdir(self.path.parent)

        self.tmp_file = tempfile.NamedTemporaryFile(
            mode="wb", dir=self.path.parent, delete=False, suffix=".tmp"
        )
        return self.tmp_file

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.tmp_file and not self.closed:
            self.tmp_file.close()

            if exc_type is None:
                # Sucesso: move atomicamente
                try:
                    os.replace(self.tmp_file.name, self.path)
                    import contextlib

                    with contextlib.suppress(OSError):
                        os.chmod(self.path, self.mode)
                except OSError:
                    # Limpa temp em caso de erro
                    import contextlib

                    with contextlib.suppress(OSError):
                        Path(self.tmp_file.name).unlink()
                    raise
            else:
                # Erro: limpa temp
                import contextlib

                with contextlib.suppress(OSError):
                    Path(self.tmp_file.name).unlink()

        self.closed = True
