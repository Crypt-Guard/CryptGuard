"""
Mensagens padronizadas da UI e tratamento de erros

Centraliza mensagens de erro/aviso e fornece funções helper
para mostrar diálogos consistentes no PySide6.
"""

import logging

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox, QWidget

logger = logging.getLogger(__name__)


def show_error(message: str, title: str = "Erro", parent: QWidget | None = None) -> None:
    """
    Mostra diálogo de erro crítico.

    Args:
        message: Mensagem de erro
        title: Título da janela
        parent: Widget pai (opcional)
    """
    logger.error(f"UI Error: {title} - {message}")

    # Se não há QApplication, apenas loga
    app = QApplication.instance()
    if app is None:
        logger.error(f"Cannot show error dialog (no QApplication): {title} - {message}")
        return

    # Cria diálogo em thread principal se necessário
    if app.thread() != QApplication.instance().thread():
        # Em casos de threads, usa invoke para thread principal
        def _show_dialog():
            QMessageBox.critical(parent, title, message)

        app.invokeMethod(app, "_show_dialog", Qt.ConnectionType.QueuedConnection)
    else:
        QMessageBox.critical(parent, title, message)


def show_warning(message: str, title: str = "Aviso", parent: QWidget | None = None) -> None:
    """
    Mostra diálogo de aviso.

    Args:
        message: Mensagem de aviso
        title: Título da janela
        parent: Widget pai (opcional)
    """
    logger.warning(f"UI Warning: {title} - {message}")

    # Se não há QApplication, apenas loga
    app = QApplication.instance()
    if app is None:
        logger.warning(f"Cannot show warning dialog (no QApplication): {title} - {message}")
        return

    if app.thread() != QApplication.instance().thread():

        def _show_dialog():
            QMessageBox.warning(parent, title, message)

        app.invokeMethod(app, "_show_dialog", Qt.ConnectionType.QueuedConnection)
    else:
        QMessageBox.warning(parent, title, message)


def show_info(message: str, title: str = "Informação", parent: QWidget | None = None) -> None:
    """
    Mostra diálogo de informação.

    Args:
        message: Mensagem informativa
        title: Título da janela
        parent: Widget pai (opcional)
    """
    logger.info(f"UI Info: {title} - {message}")

    app = QApplication.instance()
    if app is None:
        logger.info(f"Cannot show info dialog (no QApplication): {title} - {message}")
        return

    if app.thread() != QApplication.instance().thread():

        def _show_dialog():
            QMessageBox.information(parent, title, message)

        app.invokeMethod(app, "_show_dialog", Qt.ConnectionType.QueuedConnection)
    else:
        QMessageBox.information(parent, title, message)


def handle_exception(exc: Exception, context: str = "", parent: QWidget | None = None) -> None:
    """
    Trata exceção com log estruturado e diálogo de erro.

    Args:
        exc: Exceção capturada
        context: Contexto onde ocorreu o erro
        parent: Widget pai para o diálogo
    """
    error_msg = str(exc)
    if context:
        error_msg = f"{context}: {error_msg}"

    logger.exception(f"Handled exception in {context}: {exc}")

    # Mostra diálogo de erro resumido (sem traceback completo)
    show_error(error_msg, "Erro Inesperado", parent)


def handle_validation_error(message: str, parent: QWidget | None = None) -> None:
    """
    Trata erro de validação com diálogo específico.

    Args:
        message: Mensagem de validação
        parent: Widget pai
    """
    logger.warning(f"Validation error: {message}")
    show_warning(message, "Erro de Validação", parent)


def handle_permission_error(operation: str, parent: QWidget | None = None) -> None:
    """
    Trata erro de permissão.

    Args:
        operation: Operação que falhou
        parent: Widget pai
    """
    message = f"Permissão negada para: {operation}"
    logger.error(f"Permission denied: {operation}")
    show_error(message, "Erro de Permissão", parent)


def handle_file_error(operation: str, path: str, parent: QWidget | None = None) -> None:
    """
    Trata erro relacionado a arquivo.

    Args:
        operation: Operação que falhou (ler, escrever, etc.)
        path: Caminho do arquivo
        parent: Widget pai
    """
    message = f"Erro ao {operation} arquivo: {path}"
    logger.error(f"File error - {operation}: {path}")
    show_error(message, "Erro de Arquivo", parent)


# Mensagens padronizadas
class Messages:
    """Mensagens padronizadas para uso consistente."""

    # Erros de criptografia
    CRYPTO_WRONG_PASSWORD = "Senha incorreta para descriptografia"
    CRYPTO_CORRUPTED_FILE = "Arquivo corrompido ou inválido"
    CRYPTO_INVALID_KEYFILE = "Keyfile inválido ou corrompido"

    # Erros de arquivo
    FILE_NOT_FOUND = "Arquivo não encontrado"
    FILE_PERMISSION_DENIED = "Permissão negada para acessar arquivo"
    FILE_ALREADY_EXISTS = "Arquivo já existe"

    # Erros de validação
    VALIDATION_REQUIRED_FIELD = "Campo obrigatório não preenchido"
    VALIDATION_INVALID_FORMAT = "Formato inválido"
    VALIDATION_PASSWORD_TOO_SHORT = "Senha deve ter pelo menos 8 caracteres"
    VALIDATION_PASSWORD_TOO_WEAK = "Senha muito fraca"

    # Erros de rede/conexão
    NETWORK_CONNECTION_FAILED = "Falha na conexão"
    NETWORK_TIMEOUT = "Tempo limite excedido"

    # Avisos
    WARNING_OPERATION_CANCELLED = "Operação cancelada pelo usuário"
    WARNING_UNSAVED_CHANGES = "Há alterações não salvas"
    WARNING_OVERWRITE_FILE = "Isso sobrescreverá o arquivo existente"

    # Informações
    INFO_OPERATION_COMPLETED = "Operação concluída com sucesso"
    INFO_FILE_CREATED = "Arquivo criado"
    INFO_FILE_UPDATED = "Arquivo atualizado"


# Instância global para acesso fácil
messages = Messages()
