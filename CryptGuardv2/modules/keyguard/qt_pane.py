from __future__ import annotations

from crypto_core.log_utils import log_best_effort
from crypto_core.logger import logger
from crypto_core.rate_limit import (
    check_allowed,
    get_lockout_remaining,
    register_failure,
    register_success,
)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Qt (PySide6) KeyGuard sidebar for CryptGuard.
This pane mirrors the layout shown in the screenshot:
 - Right-aligned module containing a password generator
 - Length, charset options, save toggle and 'Application' field
 - Readonly password box with eye toggle, entropy bar, and actions
 - Buttons: Generate, Copy, Clear, Use in module, Vault
"""


from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QSizePolicy,
    QSpinBox,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .password_generator import CHARSETS, MIN_TOTAL_BITS, PasswordGenerator
from .vault_backend import VaultManager, WrongPassword
from .vault_qt import KeyGuardVaultDialog


class KeyGuardPaneQt(QFrame):
    def __init__(
        self,
        parent: QWidget | None = None,
        on_use_in_module: Callable[[str], None] | None = None,
        vault_opener: Callable[[], None] | None = None,
        width: int = 320,
    ):
        super().__init__(parent)
        self.setObjectName("keyguard_pane")
        self.setFixedWidth(width)
        self.setMinimumHeight(400)  # Ensure minimum height
        self.setStyleSheet(
            "QFrame#keyguard_pane{background:#212733;border-left:1px solid #1b202a;}"
        )
        self.setVisible(True)
        self.raise_()  # Bring to front

        self._on_use_in_module = on_use_in_module
        self._vault_opener = vault_opener
        self._gen = PasswordGenerator()
        self._vault_mgr: VaultManager | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        title = QLabel("KeyGuard - Generator")
        title.setStyleSheet("color:#cfd8dc;font-weight:600;")
        # Avoid forcing a specific font to prevent glyph/encoding issues
        root.addWidget(title)

        # â”€â”€ Parameters box ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
        box = QGroupBox()
        box.setStyleSheet(
            "QGroupBox{border:1px solid #2b3345;margin-top:8px;} QGroupBox:title{left:8px; padding:0 4px;}"
        )
        box.setTitle("Parameters")
        g = QGridLayout(box)
        g.setContentsMargins(8, 8, 8, 8)
        g.setHorizontalSpacing(8)
        g.setVerticalSpacing(6)

        # length
        g.addWidget(QLabel("Length:"), 0, 0, Qt.AlignRight)
        self.sp_length = QSpinBox()
        self.sp_length.setRange(4, 128)
        self.sp_length.setValue(16)
        self.sp_length.setStyleSheet(
            "QSpinBox{background:#2d3343;color:#e0e6ee;border:1px solid #3b4258;border-radius:4px;padding:4px;}"
        )
        g.addWidget(self.sp_length, 0, 1)

        # charset
        self.rb_num = QRadioButton("Numbers")
        self.rb_let = QRadioButton("Letters")
        self.rb_aln = QRadioButton("Letters+Numbers")
        self.rb_full = QRadioButton("All")
        self.rb_full.setChecked(True)
        for rb in (self.rb_num, self.rb_let, self.rb_aln, self.rb_full):
            rb.setStyleSheet("QRadioButton{color:#cfd8dc;}")
        g.addWidget(self.rb_num, 1, 0)
        g.addWidget(self.rb_let, 1, 1)
        g.addWidget(self.rb_aln, 2, 0)
        g.addWidget(self.rb_full, 2, 1)

        # save toggle + application
        self.chk_save = QCheckBox("Save in vault")
        self.chk_save.setStyleSheet("QCheckBox{color:#cfd8dc;}")
        g.addWidget(self.chk_save, 3, 0, 1, 2)

        g.addWidget(QLabel("Application:"), 4, 0, Qt.AlignRight)
        self.ed_app = QLineEdit()
        self.ed_app.setPlaceholderText("App / Site name")
        self.ed_app.setStyleSheet(
            "QLineEdit{background:#2d3343;color:#e0e6ee;border:1px solid #3b4258;border-radius:4px;padding:6px;}"
        )
        g.addWidget(self.ed_app, 4, 1)

        root.addWidget(box)

        # â”€â”€ Output ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------â”€
        out_box = QFrame()
        out_lay = QVBoxLayout(out_box)
        out_lay.setContentsMargins(0, 0, 0, 0)
        hl = QHBoxLayout()
        hl.setContentsMargins(0, 0, 0, 0)
        self.ed_pwd = QLineEdit()
        self.ed_pwd.setReadOnly(True)
        self.ed_pwd.setEchoMode(QLineEdit.Password)
        self.ed_pwd.setFont(QFont("Consolas", 11))
        self.ed_pwd.setStyleSheet(
            "QLineEdit{background:#2d3343;color:#e0e6ee;border:1px solid #3b4258;border-radius:4px;padding:8px;}"
        )
        hl.addWidget(self.ed_pwd, 1)
        self.btn_eye = QToolButton()
        self.btn_eye.setCheckable(True)
        # Avoid emoji to prevent mojibake on some systems
        self.btn_eye.setText("Show")
        self.btn_eye.clicked.connect(self._toggle_eye)
        self.btn_eye.setStyleSheet(
            "QToolButton{background:#37474F;color:#ECEFF1;border:1px solid #455A64;border-radius:6px;padding:6px;}"
        )
        hl.addWidget(self.btn_eye)
        out_lay.addLayout(hl)

        self.bar = QProgressBar()
        self.bar.setMaximum(120)
        self.bar.setStyleSheet(
            "QProgressBar{background:#2a303e;border:1px solid #1f2431;border-radius:5px;}"
            "QProgressBar::chunk{background:#29B6F6;}"
        )
        out_lay.addWidget(self.bar)

        # 🔧 FALTAVA anexar o bloco de saída ao layout principal
        root.addWidget(out_box)

        # Entropy / strength (rótulo e barra)
        self.lbl_entropy = QLabel("Entropy / strength")
        self.lbl_entropy.setStyleSheet("color:#9aa3b2")
        root.addWidget(self.lbl_entropy)

        # Botões em grade: 3 em cima (Generate/Copy/Clear), 2 embaixo (resto)
        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)
        self.btn_gen = QPushButton("Generate")
        self.btn_cpy = QPushButton("Copy")
        self.btn_clr = QPushButton("Clear")
        self.btn_entropy = QPushButton("Copy to path")
        self.btn_vault = QPushButton("Vault")
        for b in (
            self.btn_gen,
            self.btn_cpy,
            self.btn_clr,
            self.btn_entropy,
            self.btn_vault,
        ):
            b.setCursor(Qt.PointingHandCursor)
            b.setMinimumHeight(40)
            b.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        # Linha 1 (3 botões)
        grid.addWidget(self.btn_gen, 0, 0)
        grid.addWidget(self.btn_cpy, 0, 1)
        grid.addWidget(self.btn_clr, 0, 2)
        # Linha 2 (2 botões)
        grid.addWidget(self.btn_entropy, 1, 0, 1, 2)  # ocupa 2 colunas
        grid.addWidget(self.btn_vault, 1, 2)
        root.addLayout(grid)
        root.addStretch()

        # Behaviors
        self.btn_gen.clicked.connect(self._on_generate_and_maybe_save)
        self.btn_cpy.clicked.connect(self._on_copy)
        self.btn_clr.clicked.connect(self._on_clear)
        self.btn_entropy.clicked.connect(self._on_use_in_main)
        self.btn_vault.clicked.connect(self._open_keyguard_vault)

        # clipboard auto-clear
        self._clip_timer = QTimer(self)
        self._clip_timer.setSingleShot(True)
        self._clip_timer.timeout.connect(self._clear_clipboard)

    # â”€â”€ helpers ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------â”€â”€
    def _toggle_eye(self):
        # Check if ed_pwd is still valid before using it
        if not hasattr(self, "ed_pwd") or self.ed_pwd is None:
            return
        try:
            if self.btn_eye.isChecked():
                self.ed_pwd.setEchoMode(QLineEdit.Normal)
                self.btn_eye.setText("Hide")
            else:
                self.ed_pwd.setEchoMode(QLineEdit.Password)
                self.btn_eye.setText("Show")
        except RuntimeError as e:
            # Object was deleted, skip this operation
            logger.debug("KeyGuard: Objeto deletado durante operação: %s", e)
            pass

    def _read_length(self) -> int:
        n = max(4, min(128, int(self.sp_length.value())))
        self.sp_length.setValue(n)
        return n

    def _current_charset(self) -> str:
        if self.rb_num.isChecked():
            key = "numbers"
        elif self.rb_let.isChecked():
            key = "letters"
        elif self.rb_aln.isChecked():
            key = "alphanumeric"
        else:
            key = "full"
        return CHARSETS[key]

    # â”€â”€ actions ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------â”€â”€
    def _on_generate(self):
        length = self._read_length()
        charset = self._current_charset()
        pwd = self._gen.generate(length, charset)

        # Check if ed_pwd is still valid before using it
        if hasattr(self, "ed_pwd") and self.ed_pwd is not None:
            try:
                self.ed_pwd.setText(pwd)
            except RuntimeError as e:
                # Object was deleted, skip this operation
                logger.debug("KeyGuard: Objeto deletado durante geração: %s", e)
                return

        bits = PasswordGenerator.calculate_entropy(pwd, charset)
        self.bar.setValue(min(int(bits), 120))
        classes = sum(
            [
                any(c.islower() for c in pwd),
                any(c.isupper() for c in pwd),
                any(c.isdigit() for c in pwd),
                any(not c.isalnum() for c in pwd),
            ]
        )
        msg = f"Entropy: {bits:.1f} bits"
        if bits < MIN_TOTAL_BITS or classes < 2:
            msg += "  WARNING"
        self.lbl_entropy.setText(msg)

    def _on_copy(self):
        # Check if ed_pwd is still valid before using it
        if not hasattr(self, "ed_pwd") or self.ed_pwd is None:
            return
        try:
            s = self.ed_pwd.text()
            if not s:
                return
            QGuiApplication.clipboard().setText(s)
        except RuntimeError as e:
            # Object was deleted, skip this operation
            logger.debug("KeyGuard: Objeto deletado durante cópia: %s", e)
            return
        self._clip_timer.start(15000)  # auto-clear after 15s

    def _clear_clipboard(self):
        QGuiApplication.clipboard().clear()

    def _on_clear(self):
        self._clear_clipboard()
        # Check if ed_pwd is still valid before using it
        if hasattr(self, "ed_pwd") and self.ed_pwd is not None:
            try:
                self.ed_pwd.clear()
            except RuntimeError as e:
                # Object was deleted, skip this operation
                logger.debug("KeyGuard: Objeto deletado durante limpeza: %s", e)
                pass
        self.bar.setValue(0)
        self.lbl_entropy.setText("Entropy / strength")
        self.btn_eye.setChecked(False)
        self._toggle_eye()

    def _on_use_in_main(self):
        # Check if ed_pwd is still valid before using it
        if not hasattr(self, "ed_pwd") or self.ed_pwd is None:
            return
        try:
            pwd = self.ed_pwd.text()
            if pwd and self._on_use_in_module:
                self._on_use_in_module(pwd)
        except RuntimeError as e:
            # Object was deleted, skip this operation
            logger.debug("KeyGuard: Objeto deletado durante uso: %s", e)
            return

    # ---- generate + optional save to KeyGuard Vault --------------------
    def _on_generate_and_maybe_save(self) -> None:
        """Gera a senha e, se marcado 'Save in vault', salva/atualiza no Vault."""
        self._on_generate()
        try:
            if self.chk_save.isChecked():
                name = (self.ed_app.text() or "Unnamed").strip()
                # Check if ed_pwd is still valid before using it
                if not hasattr(self, "ed_pwd") or self.ed_pwd is None:
                    return
                try:
                    pwd = self.ed_pwd.text()
                except RuntimeError as e:
                    # Object was deleted, skip this operation
                    logger.debug("KeyGuard: Objeto deletado durante geração e salvamento: %s", e)
                    return
                if name and pwd:
                    mgr = self._ensure_kv_opened()
                    if mgr:
                        # Backend novo expõe add_or_update_entry / upsert_entry
                        if hasattr(mgr, "add_or_update_entry"):
                            mgr.add_or_update_entry(name, pwd)
                        elif hasattr(mgr, "upsert_entry"):
                            mgr.upsert_entry(name, pwd)
                        else:
                            # Fallback legado, se existir API antiga
                            entries = getattr(mgr, "entries", {})
                            if name in entries and hasattr(mgr, "update_entry"):
                                mgr.update_entry(name, password=pwd)
                            elif hasattr(mgr, "add_entry"):
                                mgr.add_entry(name, pwd)
        except FileNotFoundError as e:
            logger.vault_error(
                "save_password",
                "KeyGuard",
                e,
                {
                    "vault_path": getattr(mgr, "path", "unknown")
                    if "mgr" in locals()
                    else "unknown",
                    "password_name": name if "name" in locals() else "unknown",
                    "ui_context": "keyguard_generate_and_save",
                },
            )
            QMessageBox.warning(self, "Vault", f"Arquivo de vault não encontrado:\n{e}")
        except PermissionError as e:
            logger.vault_error(
                "save_password",
                "KeyGuard",
                e,
                {
                    "vault_path": getattr(mgr, "path", "unknown")
                    if "mgr" in locals()
                    else "unknown",
                    "password_name": name if "name" in locals() else "unknown",
                    "ui_context": "keyguard_generate_and_save",
                },
            )
            QMessageBox.warning(self, "Vault", f"Sem permissão para salvar no vault:\n{e}")
        except Exception as e:
            logger.vault_error(
                "save_password",
                "KeyGuard",
                e,
                {
                    "vault_path": getattr(mgr, "path", "unknown")
                    if "mgr" in locals()
                    else "unknown",
                    "password_name": name if "name" in locals() else "unknown",
                    "ui_context": "keyguard_generate_and_save",
                    "vault_manager_available": "mgr" in locals() and mgr is not None,
                },
            )
            QMessageBox.warning(self, "Vault Error", f"Não foi possível salvar a senha:\n{e}")

    # ---- KeyGuard Vault integration ------------------------------------
    def _ensure_kv_opened(self) -> VaultManager | None:
        """Abre/cria o Vault do KeyGuard on-demand e cacheia o manager."""
        if self._vault_mgr is not None:
            return self._vault_mgr

        # P1.5: Rate limiting - verificar se está em lockout

        vault_id = "keyguard_vault_open"

        if not check_allowed(vault_id, max_failures=5, lockout_time=300.0):  # 5 min lockout
            remaining = get_lockout_remaining(vault_id, max_failures=5, lockout_time=300.0)

            QMessageBox.warning(
                self,
                "Vault Bloqueado",
                f"Muitas tentativas incorretas. Tente novamente em {int(remaining)} segundos.",
            )
            return None

        mpw, ok = QInputDialog.getText(
            self, "KeyGuard Vault", "Master password:", echo=QLineEdit.Password
        )  # type: ignore
        if not ok or not mpw:
            return None
        mpw_b = mpw.encode("utf-8") if isinstance(mpw, str) else mpw
        mgr = VaultManager()
        try:
            # Tenta abrir vault existente
            mgr.open(mpw_b)
            # P1.5: Sucesso - limpar contador de falhas

            register_success(vault_id)
            self._vault_mgr = mgr
            return mgr
        except FileNotFoundError:
            # Não existe: pergunta ao usuário se deseja criar
            dest = getattr(mgr, "path", None) if hasattr(mgr, "path") else None
            if (
                QMessageBox.question(
                    self,
                    "Criar Vault (KeyGuard)",
                    f"Nenhum vault encontrado. Criar um novo?\n{dest}",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                )
                != QMessageBox.Yes
            ):
                return None
            try:
                if hasattr(mgr, "path") and getattr(mgr, "path", None):
                    Path(mgr.path).parent.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                log_best_effort(__name__, exc)
            mgr.create(mpw_b)
            self._vault_mgr = mgr
            return mgr
        except WrongPassword as ex:
            # P1.5: Registrar falha para rate limiting

            register_failure(vault_id)

            logger.vault_error(
                "open",
                "KeyGuard",
                ex,
                {
                    "vault_path": getattr(mgr, "path", "unknown"),
                    "attempted_operation": "open_vault",
                    "ui_context": "keyguard_pane",
                },
            )
            QMessageBox.warning(self, "Vault", "Senha do KeyGuard incorreta.")
            return None
        except Exception as ex:
            logger.vault_error(
                "open/create",
                "KeyGuard",
                ex,
                {
                    "vault_path": getattr(mgr, "path", "unknown"),
                    "attempted_operation": "ensure_kv_opened",
                    "ui_context": "keyguard_pane",
                    "vault_exists": hasattr(mgr, "path") and Path(mgr.path).exists()
                    if hasattr(mgr, "path")
                    else False,
                },
            )
            QMessageBox.critical(self, "Error", f"Failed to open/create KeyGuard vault:\n{ex}")
            return None

    def _open_keyguard_vault(self) -> None:
        mgr = self._ensure_kv_opened()
        if not mgr:
            return
        dlg = KeyGuardVaultDialog(self, mgr)
        dlg.exec()


def attach_keyguard_qt(app: QWidget, width: int = 320):
    """
    Attaches the KeyGuardQt pane to the right side of a parent that has
    an attribute `body_layout` (QHBoxLayout) and a QLineEdit password field
    named `password_input`. This matches the project's MainWindow.
    """
    try:
        body = getattr(app, "body_layout", None)
        if body is None:
            raise AttributeError("MainWindow is missing body_layout for right sidebar.")

        def use_in_module(pwd: str):
            if hasattr(app, "password_input"):
                app.password_input.setText(pwd)
                app.status_bar.showMessage("Password filled from KeyGuard.")

        pane = KeyGuardPaneQt(
            app,
            on_use_in_module=use_in_module,
            vault_opener=getattr(app, "_open_vault", None),
            width=width,
        )
        # fixa largura e alinha o painel à direita do body_layout
        body.addWidget(pane, 0, Qt.AlignRight)
        pane.setVisible(True)
        app.keyguard_pane = pane
        return pane
    except Exception as e:
        # Defer to app logger if available
        try:
            logger.warning("KeyGuard Qt attach failed: %s", e)
        except Exception as exc:
            log_best_effort(__name__, exc)
        return None
