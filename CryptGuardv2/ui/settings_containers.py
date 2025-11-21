"""
UI para Modo de Compartilhamento Seguro (Secure Containers).

Fornece dialogs para:
- Criar containers (.vault) a partir de seleções dos vaults
- Ler containers e integrar/extrair itens
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Literal

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWizard,
    QWizardPage,
)

from containers.secure_container import (
    ContainerEntry,
    CorruptContainerError,
    SecureContainerReader,
    SecureContainerWriter,
    WrongPasswordError,
)
from crypto_core.logger import logger
from integration.container_bridge import (
    IntegrateReport,
    collect_from_cryptguard,
    collect_from_keyguard,
    integrate_into_cryptguard,
    integrate_into_keyguard,
)


# ============================================================================
# Criar Container (Wizard em 3 passos)
# ============================================================================


class SelectCryptGuardPage(QWizardPage):
    """Página 1: Selecionar itens do CryptGuard Vault."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Selecionar Arquivos do CryptGuard")
        self.setSubTitle("Escolha os arquivos cifrados (.cg2) a incluir no container")

        layout = QVBoxLayout()

        # Lista de itens
        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        layout.addWidget(self.list_widget)

        # Botões de seleção
        btn_layout = QHBoxLayout()
        btn_select_all = QPushButton("Selecionar Tudo")
        btn_select_none = QPushButton("Nenhum")
        btn_select_all.clicked.connect(self.select_all)
        btn_select_none.clicked.connect(self.select_none)
        btn_layout.addWidget(btn_select_all)
        btn_layout.addWidget(btn_select_none)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.setLayout(layout)

    def populate_items(self, items: list[dict[str, Any]]) -> None:
        """Popula lista com itens do vault."""
        self.list_widget.clear()
        for item in items:
            name = item.get("name", "Unnamed")
            size = item.get("size", 0)
            text = f"{name} ({size} bytes)"
            list_item = QListWidgetItem(text)
            list_item.setData(Qt.ItemDataRole.UserRole, item)
            self.list_widget.addItem(list_item)

    def get_selected_items(self) -> list[dict[str, Any]]:
        """Retorna itens selecionados."""
        items = []
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if item.isSelected():
                items.append(item.data(Qt.ItemDataRole.UserRole))
        return items

    def select_all(self) -> None:
        """Seleciona todos os itens."""
        self.list_widget.selectAll()

    def select_none(self) -> None:
        """Desmarca todos os itens."""
        self.list_widget.clearSelection()


class SelectKeyGuardPage(QWizardPage):
    """Página 2: Selecionar entradas do KeyGuard Vault."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Selecionar Entradas do KeyGuard")
        self.setSubTitle("Escolha as entradas de senhas/segredos a incluir no container")

        layout = QVBoxLayout()

        # Lista de entradas
        self.list_widget = QListWidget()
        self.list_widget.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        layout.addWidget(self.list_widget)

        # Botões de seleção
        btn_layout = QHBoxLayout()
        btn_select_all = QPushButton("Selecionar Tudo")
        btn_select_none = QPushButton("Nenhum")
        btn_select_all.clicked.connect(self.select_all)
        btn_select_none.clicked.connect(self.select_none)
        btn_layout.addWidget(btn_select_all)
        btn_layout.addWidget(btn_select_none)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.setLayout(layout)

    def populate_entries(self, entries: list[dict[str, Any]]) -> None:
        """Popula lista com entradas do vault."""
        self.list_widget.clear()
        for entry in entries:
            name = entry.get("name", "Unnamed")
            tags = entry.get("metadata", {}).get("tags", [])
            tags_str = ", ".join(tags) if tags else "Sem tags"
            text = f"{name} ({tags_str})"
            list_item = QListWidgetItem(text)
            list_item.setData(Qt.ItemDataRole.UserRole, entry)
            self.list_widget.addItem(list_item)

    def get_selected_entries(self) -> list[dict[str, Any]]:
        """Retorna entradas selecionadas."""
        entries = []
        for i in range(self.list_widget.count()):
            item = self.list_widget.item(i)
            if item.isSelected():
                entries.append(item.data(Qt.ItemDataRole.UserRole))
        return entries

    def select_all(self) -> None:
        """Seleciona todos os itens."""
        self.list_widget.selectAll()

    def select_none(self) -> None:
        """Desmarca todos os itens."""
        self.list_widget.clearSelection()


class ConfigureContainerPage(QWizardPage):
    """Página 3: Configurar Container (senha, local, etc.)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Configurar Container")
        self.setSubTitle("Defina a senha e o local do container")

        layout = QFormLayout()

        # Senha do container
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Digite a senha do container")
        layout.addRow("Senha do Container:", self.password_input)

        # Confirmar senha
        self.password_confirm = QLineEdit()
        self.password_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_confirm.setPlaceholderText("Confirme a senha")
        layout.addRow("Confirmar Senha:", self.password_confirm)

        # Botão mostrar/ocultar senha
        self.show_password_checkbox = QCheckBox("Mostrar senha")
        self.show_password_checkbox.stateChanged.connect(self.toggle_password_visibility)
        layout.addRow("", self.show_password_checkbox)

        # Local do container
        container_layout = QHBoxLayout()
        self.container_path_input = QLineEdit()
        self.container_path_input.setPlaceholderText("Escolha o local e nome do container")
        btn_browse = QPushButton("Escolher...")
        btn_browse.clicked.connect(self.browse_container_path)
        container_layout.addWidget(self.container_path_input)
        container_layout.addWidget(btn_browse)
        layout.addRow("Local do Container:", container_layout)

        # Perfil KDF
        self.kdf_profile_combo = QComboBox()
        self.kdf_profile_combo.addItems(["moderate", "strong"])
        self.kdf_profile_combo.setCurrentText("moderate")
        layout.addRow("Perfil de Segurança:", self.kdf_profile_combo)

        # Resumo
        self.summary_label = QLabel("0 arquivos CryptGuard e 0 segredos KeyGuard selecionados")
        layout.addRow("Resumo:", self.summary_label)

        self.setLayout(layout)

        # Sugerir nome padrão
        default_name = f"Compartilhamento-{time.strftime('%Y-%m-%d')}.vault"
        default_path = Path.home() / default_name
        self.container_path_input.setText(str(default_path))

    def toggle_password_visibility(self, state: int) -> None:
        """Alterna visibilidade da senha."""
        if state == Qt.CheckState.Checked.value:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.password_confirm.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.password_confirm.setEchoMode(QLineEdit.EchoMode.Password)

    def browse_container_path(self) -> None:
        """Abre dialog para escolher local do container."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Salvar Container",
            str(Path.home()),
            "Vault Files (*.vault);;All Files (*)",
        )
        if file_path:
            # Garantir extensão .vault
            path = Path(file_path)
            if path.suffix.lower() != ".vault":
                path = path.with_suffix(".vault")
            self.container_path_input.setText(str(path))

    def update_summary(self, cg_count: int, kg_count: int) -> None:
        """Atualiza resumo de seleção."""
        self.summary_label.setText(
            f"{cg_count} arquivo(s) CryptGuard e {kg_count} segredo(s) KeyGuard selecionados"
        )

    def validatePage(self) -> bool:
        """Valida campos antes de prosseguir."""
        password = self.password_input.text()
        confirm = self.password_confirm.text()

        if not password:
            QMessageBox.warning(self, "Senha Vazia", "Por favor, digite uma senha para o container.")
            return False

        if password != confirm:
            QMessageBox.warning(self, "Senhas Não Coincidem", "As senhas não coincidem. Verifique e tente novamente.")
            return False

        # Avisar sobre espaços
        if password.startswith(" ") or password.endswith(" "):
            reply = QMessageBox.question(
                self,
                "Espaços na Senha",
                "A senha contém espaços no início ou fim. Isso pode dificultar o uso.\n\nDeseja continuar?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return False

        container_path = self.container_path_input.text()
        if not container_path:
            QMessageBox.warning(self, "Local Não Definido", "Por favor, escolha o local do container.")
            return False

        return True


class ContainerCreateDialog(QWizard):
    """Wizard para criar secure container."""

    def __init__(self, cg_items: list[dict[str, Any]], kg_entries: list[dict[str, Any]], cg_vault_dir: Path, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Criar Secure Container")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.resize(700, 500)

        # Dados
        self.cg_items = cg_items
        self.kg_entries = kg_entries
        self.cg_vault_dir = cg_vault_dir

        # Páginas
        self.page_cg = SelectCryptGuardPage()
        self.page_kg = SelectKeyGuardPage()
        self.page_config = ConfigureContainerPage()

        self.addPage(self.page_cg)
        self.addPage(self.page_kg)
        self.addPage(self.page_config)

        # Popular listas
        self.page_cg.populate_items(cg_items)
        self.page_kg.populate_entries(kg_entries)

        # Conectar sinais para atualizar resumo
        self.currentIdChanged.connect(self.on_page_changed)

    def on_page_changed(self, page_id: int) -> None:
        """Atualiza resumo quando mudar de página."""
        if page_id == 2:  # Página de configuração
            cg_count = len(self.page_cg.get_selected_items())
            kg_count = len(self.page_kg.get_selected_entries())
            self.page_config.update_summary(cg_count, kg_count)

    def accept(self) -> None:
        """Cria o container ao finalizar."""
        try:
            # Coletar seleções
            selected_cg = self.page_cg.get_selected_items()
            selected_kg = self.page_kg.get_selected_entries()

            if not selected_cg and not selected_kg:
                QMessageBox.warning(
                    self,
                    "Nenhum Item Selecionado",
                    "Por favor, selecione ao menos um item para incluir no container.",
                )
                return

            # Configurações
            password = self.page_config.password_input.text().encode("utf-8")
            container_path = Path(self.page_config.container_path_input.text())
            kdf_profile = self.page_config.kdf_profile_combo.currentText()

            # Criar container
            logger.info("Criando container: %s", container_path)

            with SecureContainerWriter(container_path, password, kdf_profile) as writer:
                # Manifest
                manifest = {
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "cg_count": len(selected_cg),
                    "kg_count": len(selected_kg),
                    "version": 1,
                }
                writer.add_manifest(manifest)

                # Coletar e adicionar itens CryptGuard
                if selected_cg:
                    cg_entries = collect_from_cryptguard(selected_cg, self.cg_vault_dir)
                    for entry in cg_entries:
                        writer.add_cg_file(
                            name=entry.name,
                            data=entry.data,
                            meta=entry.meta,
                        )

                # Coletar e adicionar entradas KeyGuard
                if selected_kg:
                    kg_entries = collect_from_keyguard(selected_kg)
                    for entry in kg_entries:
                        writer.add_kg_secret(
                            name=entry.name,
                            json_bytes_gz=entry.data,
                            meta=entry.meta,
                        )

                writer.finalize()

            # Sucesso
            QMessageBox.information(
                self,
                "Container Criado",
                f"Container criado com sucesso:\n{container_path}\n\n"
                f"{len(selected_cg)} arquivo(s) e {len(selected_kg)} segredo(s) incluídos.",
            )

            # Abrir pasta
            reply = QMessageBox.question(
                self,
                "Abrir Pasta",
                "Deseja abrir a pasta do container?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.open_folder(container_path.parent)

            super().accept()

        except Exception as e:
            logger.error("Erro ao criar container: %s", e, exc_info=True)
            QMessageBox.critical(
                self,
                "Erro ao Criar Container",
                f"Não foi possível criar o container:\n{e}",
            )

    @staticmethod
    def open_folder(folder: Path) -> None:
        """Abre pasta no gerenciador de arquivos."""
        try:
            if os.name == "nt":
                os.startfile(folder)
            elif os.name == "posix":
                import subprocess
                subprocess.Popen(["xdg-open", str(folder)])
        except Exception as e:
            logger.warning("Não foi possível abrir pasta: %s", e)


# ============================================================================
# Ler Container
# ============================================================================


class ContainerReadDialog(QDialog):
    """Dialog para ler e integrar/extrair itens de container."""

    def __init__(self, container_path: Path, password: bytes, parent=None, main_window=None):
        super().__init__(parent)
        self.setWindowTitle(f"Container: {container_path.name}")
        self.resize(900, 600)

        self.container_path = container_path
        self.password = password
        self.entries: list[ContainerEntry] = []
        self.main_window = main_window  # Referência ao MainWindow para acesso aos vaults

        # Layout principal
        layout = QVBoxLayout()

        # Título
        title_label = QLabel(f"<h3>Container: {container_path.name}</h3>")
        layout.addWidget(title_label)

        # Tabela de itens
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Tipo", "Nome", "Tamanho/Info", "Criado", "Modificado"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.MultiSelection)
        layout.addWidget(self.table)

        # Botões de ação
        btn_layout = QHBoxLayout()

        self.btn_integrate = QPushButton("Integrar nos Vaults")
        self.btn_integrate.clicked.connect(self.integrate_items)
        btn_layout.addWidget(self.btn_integrate)

        self.btn_extract = QPushButton("Extrair Arquivos Para...")
        self.btn_extract.clicked.connect(self.extract_files)
        btn_layout.addWidget(self.btn_extract)

        btn_layout.addStretch()

        btn_close = QPushButton("Fechar")
        btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(btn_close)

        layout.addLayout(btn_layout)

        self.setLayout(layout)

        # Carregar container
        self.load_container()

    def load_container(self) -> None:
        """Carrega container e popula tabela."""
        try:
            logger.info("Lendo container: %s", self.container_path)

            with SecureContainerReader(self.container_path, self.password) as reader:
                self.entries = reader.read_all()

            # Filtrar manifest
            self.entries = [e for e in self.entries if e.type != "manifest"]

            # Popular tabela
            self.table.setRowCount(len(self.entries))

            for row, entry in enumerate(self.entries):
                # Tipo
                type_text = "Arquivo" if entry.type == "cg_file" else "Segredo"
                self.table.setItem(row, 0, QTableWidgetItem(type_text))

                # Nome
                self.table.setItem(row, 1, QTableWidgetItem(entry.name))

                # Tamanho/Info
                if entry.type == "cg_file":
                    info = f"{len(entry.data)} bytes"
                else:
                    tags = entry.meta.get("tags", [])
                    info = ", ".join(tags) if tags else "Sem tags"
                self.table.setItem(row, 2, QTableWidgetItem(info))

                # Datas
                self.table.setItem(row, 3, QTableWidgetItem(entry.created_at[:10]))
                self.table.setItem(row, 4, QTableWidgetItem(entry.modified_at[:10]))

            self.table.resizeColumnsToContents()

            logger.info("Container carregado: %d entradas", len(self.entries))

        except WrongPasswordError as e:
            logger.error("Senha incorreta para container: %s", e)
            QMessageBox.critical(
                self,
                "Senha Incorreta",
                "Falha na verificação do container. Possíveis causas:\n"
                "- Senha incorreta\n"
                "- Arquivo corrompido",
            )
            self.reject()

        except CorruptContainerError as e:
            logger.error("Container corrompido: %s", e)
            QMessageBox.critical(
                self,
                "Container Corrompido",
                f"O container está corrompido ou foi modificado:\n{e}",
            )
            self.reject()

        except Exception as e:
            logger.error("Erro ao ler container: %s", e, exc_info=True)
            QMessageBox.critical(
                self,
                "Erro ao Ler Container",
                f"Não foi possível ler o container:\n{e}",
            )
            self.reject()

    def get_selected_entries(self) -> list[ContainerEntry]:
        """Retorna entradas selecionadas na tabela."""
        selected_rows = set(item.row() for item in self.table.selectedItems())
        return [self.entries[row] for row in sorted(selected_rows)]

    def _get_keyguard_vault(self):
        """Obtém o vault manager do KeyGuard se estiver aberto."""
        if self.main_window is None:
            return None
        
        # Tenta obter o painel do KeyGuard
        keyguard_pane = getattr(self.main_window, "keyguard_pane", None)
        if keyguard_pane is None:
            return None
        
        # Tenta obter o vault manager do painel
        vault_mgr = getattr(keyguard_pane, "_vault_mgr", None)
        if vault_mgr is None:
            return None
        
        # Verifica se o vault está aberto
        if not getattr(vault_mgr, "_opened", False):
            return None
        
        return vault_mgr

    def integrate_items(self) -> None:
        """Integra itens selecionados nos vaults."""
        selected = self.get_selected_entries()

        if not selected:
            QMessageBox.warning(
                self,
                "Nenhum Item Selecionado",
                "Por favor, selecione ao menos um item para integrar.",
            )
            return

        # Perguntar modo de conflito
        conflict_mode = self.ask_conflict_mode()
        if conflict_mode is None:
            return

        # Separar por tipo
        cg_entries = [e for e in selected if e.type == "cg_file"]
        kg_entries = [e for e in selected if e.type == "kg_secret"]

        reports = []

        # Integrar CryptGuard
        if cg_entries:
            # TODO: Obter vault_dir do contexto
            vault_dir = Path.home() / "CryptGuard" / "vault"
            vault_dir.mkdir(parents=True, exist_ok=True)

            report = integrate_into_cryptguard(cg_entries, vault_dir, conflict_mode)
            reports.append(("CryptGuard", report))

        # Integrar KeyGuard
        if kg_entries:
            vault_mgr = self._get_keyguard_vault()
            if vault_mgr is None:
                QMessageBox.warning(
                    self,
                    "Vault KeyGuard Não Aberto",
                    "Para integrar senhas no KeyGuard, é necessário abrir o vault primeiro.\n\n"
                    "1. Clique em 'Vault' no painel KeyGuard (lado direito)\n"
                    "2. Insira a senha master do KeyGuard\n"
                    "3. Tente novamente a integração",
                )
            else:
                try:
                    report = integrate_into_keyguard(kg_entries, vault_mgr, conflict_mode)
                    reports.append(("KeyGuard", report))
                except Exception as e:
                    logger.error("Erro ao integrar no KeyGuard: %s", e, exc_info=True)
                    QMessageBox.critical(
                        self,
                        "Erro na Integração KeyGuard",
                        f"Não foi possível integrar as senhas no KeyGuard:\n{e}",
                    )

        # Mostrar relatório
        if reports:
            self.show_integration_report(reports)

    def ask_conflict_mode(self) -> Literal["skip", "duplicate", "replace"] | None:
        """Pergunta ao usuário como tratar conflitos."""
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Tratamento de Conflitos")
        dialog.setText("Como deseja tratar itens que já existem nos vaults?")
        dialog.setIcon(QMessageBox.Icon.Question)

        btn_skip = dialog.addButton("Pular", QMessageBox.ButtonRole.ActionRole)
        btn_duplicate = dialog.addButton("Duplicar (com sufixo)", QMessageBox.ButtonRole.ActionRole)
        btn_replace = dialog.addButton("Substituir", QMessageBox.ButtonRole.ActionRole)
        dialog.addButton(QMessageBox.StandardButton.Cancel)

        dialog.exec()

        clicked = dialog.clickedButton()
        if clicked == btn_skip:
            return "skip"
        elif clicked == btn_duplicate:
            return "duplicate"
        elif clicked == btn_replace:
            return "replace"
        else:
            return None

    def show_integration_report(self, reports: list[tuple[str, IntegrateReport]]) -> None:
        """Mostra relatório de integração."""
        msg = "Integração concluída:\n\n"

        for vault_type, report in reports:
            msg += f"{vault_type}:\n"
            msg += f"  - Total: {report.total}\n"
            msg += f"  - Integrados: {report.integrated}\n"
            msg += f"  - Pulados: {report.skipped}\n"
            msg += f"  - Duplicados: {report.duplicated}\n"

            if report.errors:
                msg += f"  - Erros: {len(report.errors)}\n"
                for err in report.errors[:5]:  # Mostrar apenas 5 primeiros
                    msg += f"    • {err}\n"

            msg += "\n"

        QMessageBox.information(self, "Relatório de Integração", msg)

    def extract_files(self) -> None:
        """Extrai arquivos selecionados para diretório."""
        selected = self.get_selected_entries()

        # Filtrar apenas cg_file
        cg_files = [e for e in selected if e.type == "cg_file"]

        if not cg_files:
            QMessageBox.warning(
                self,
                "Nenhum Arquivo Selecionado",
                "Por favor, selecione ao menos um arquivo (tipo CryptGuard) para extrair.",
            )
            return

        # Escolher diretório
        extract_dir = QFileDialog.getExistingDirectory(
            self,
            "Escolher Diretório de Destino",
            str(Path.home()),
        )

        if not extract_dir:
            return

        extract_path = Path(extract_dir)

        # Extrair arquivos
        success_count = 0
        errors = []

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

                file_path = extract_path / safe_name

                # Evitar sobrescrever
                if file_path.exists():
                    stem = file_path.stem
                    suffix = file_path.suffix
                    counter = 1
                    while file_path.exists():
                        file_path = extract_path / f"{stem}({counter}){suffix}"
                        counter += 1

                # Gravar
                file_path.write_bytes(entry.data)
                success_count += 1
                logger.info("Arquivo extraído: %s", file_path)

            except Exception as e:
                logger.error("Erro ao extrair %s: %s", entry.name, e)
                errors.append(f"{entry.name}: {e}")

        # Relatório
        msg = f"Extração concluída:\n\n"
        msg += f"Arquivos extraídos: {success_count}/{len(cg_files)}\n"

        if errors:
            msg += f"\nErros:\n"
            for err in errors[:5]:
                msg += f"  • {err}\n"

        QMessageBox.information(self, "Extração Concluída", msg)

        # Abrir pasta
        if success_count > 0:
            reply = QMessageBox.question(
                self,
                "Abrir Pasta",
                "Deseja abrir a pasta de destino?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                ContainerCreateDialog.open_folder(extract_path)


__all__ = [
    "ContainerCreateDialog",
    "ContainerReadDialog",
]

