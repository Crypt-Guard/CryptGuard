#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CryptGuardv2 - secure GUI
Versao com interface classica e core refatorado compativel com vault_v2.py e cg2_ops_v2.py
"""

from __future__ import annotations

# --------------------------------------------------------------- Standard library ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------â”€â”€
import contextlib
import locale
import os
import shutil
import sys
import time
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional, Any
import warnings

# --------------------------------------------------------------- PySide6 / Qt ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
from PySide6.QtCore import (
    QDate,
    QEasingCurve,
    QEvent,
    QPoint,
    QPropertyAnimation,
    Qt,
    QThread,
    QTimer,
    QUrl,
    Signal,
    QSize,  # added
)
from PySide6.QtGui import (
    QBrush,
    QColor,
    QDesktopServices,
    QDragEnterEvent,
    QDropEvent,
    QFont,
    QLinearGradient,
    QPainter,
    QPalette,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStatusBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

# --------------------------------------------------------------- Configuração de warnings e encoding ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*utcfromtimestamp.*")

# stdout/stderr UTF-8 no Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Configuração de locale
try:
    locale.setlocale(locale.LC_ALL, "")
except Exception:
    pass

# --------------------------------------------------------------- Imports do Projeto ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
from crypto_core.factories import encrypt as cg_encrypt, decrypt as cg_decrypt
from crypto_core.secure_bytes import SecureBytes

# Imports do Vault com fallback apropriado
try:
    from vault import (
        Config,
        CorruptVault,
        SecureMemory,
        VaultDialog,
        VaultManager,
        WrongPassword,
        VaultLocked,
        AtomicStorageBackend,
        open_or_init_vault,
    )
    USING_V2 = True
except ImportError as e:
    # Define classes mÃ­nimas para compatibilidade
    class VaultLocked(Exception):
        pass
    
    class AtomicStorageBackend:
        def __init__(self, path):
            self.path = Path(path)
            self.path.parent.mkdir(parents=True, exist_ok=True)
        
        def save(self, data: bytes):
            self.path.write_bytes(data)
        
        def load(self) -> bytes:
            return self.path.read_bytes() if self.path.exists() else b""
    
    # Re-importa com classes definidas
    from vault import (
        Config,
        CorruptVault,
        SecureMemory,
        VaultDialog,
        VaultManager,
        WrongPassword,
        open_or_init_vault,
    )
    USING_V2 = False
    
    # Define VaultLocked se não existir
    if not 'VaultLocked' in locals():
        class VaultLocked(Exception):
            pass

from crypto_core import LOG_PATH
from crypto_core.fileformat import is_cg2_file, read_header
from crypto_core.logger import logger
from crypto_core.utils import secure_delete, archive_folder
from crypto_core.verify_integrity import verify_integrity

# --- NEW: KeyGuard sidebar (Qt) ---
# Carrega o helper com fallback robusto caso o pacote não esteja em modules/keyguard/.
attach_keyguard_qt = None
try:
    from modules.keyguard import attach_keyguard_qt  # caminho preferido
except Exception:
    attach_keyguard_qt = None
    try:
        import importlib.util, pathlib
        _BASE = pathlib.Path(__file__).resolve().parent
        for _cand in (
            _BASE / "modules" / "keyguard" / "qt_pane.py",
            _BASE / "qt_pane.py",
        ):
            if _cand.exists():
                _spec = importlib.util.spec_from_file_location("keyguard_qt_pane", _cand)
                _mod = importlib.util.module_from_spec(_spec)  # type: ignore
                assert _spec and _spec.loader
                _spec.loader.exec_module(_mod)                 # type: ignore
                attach_keyguard_qt = getattr(_mod, "attach_keyguard_qt", None)
                if attach_keyguard_qt:
                    break
    except Exception:
        attach_keyguard_qt = None

# --------------------------------------------------------------- Detecção de algoritmos disponiveis ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------â”€
ALGOS = ["AES-256-GCM", "AES-256-CTR", "ChaCha20-Poly1305"]

# Detecta XChaCha20
try:
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
    XCHACHA20_AVAILABLE = True
    ALGOS.append("XChaCha20-Poly1305")
except ImportError:
    XCHACHA20_AVAILABLE = False  # Legacy detection not used in v5 UI

# ------------------------------------------------------------------------------------------------------------------------------â•â•
#                              UI HELPERS (Estilo Antigo)
# ------------------------------------------------------------------------------------------------------------------------------â•â•

def human_speed(bytes_processed: int, elapsed_seconds: float) -> str:
    """Formata velocidade de transferência."""
    if elapsed_seconds <= 0:
        return "- MB/s"
    bps = bytes_processed / elapsed_seconds
    if bps < 1024:
        return f"{bps:.1f} B/s"
    if bps < 1024 * 1024:
        return f"{bps / 1024:.1f} KB/s"
    if bps < 1024 * 1024 * 1024:
        return f"{bps / (1024 * 1024):.1f} MB/s"
    return f"{bps / (1024 * 1024 * 1024):.1f} GB/s"

class ClickableDateEdit(QDateEdit):
    """DateEdit que abre o calendário ao clicar no campo inteiro."""
    
    def mousePressEvent(self, event):
        if self.isEnabled() and self.calendarPopup():
            for child in self.children():
                if isinstance(child, QToolButton):
                    child.click()
                    break
        super().mousePressEvent(event)

class AccentButton(QPushButton):
    """Botão azul com animação de hover (estilo antigo)."""
    
    def __init__(self, text: str):
        super().__init__(text)
        self.setCursor(Qt.PointingHandCursor)
        self._base = "#536dfe"
        self._hover = "#7c9dff"
        self._radius = 9
        self._update_css(self._base)
        self._anim = QPropertyAnimation(self, b"geometry", self)
        self._anim.setDuration(150)
        self._anim.setEasingCurve(QEasingCurve.OutQuad)
    
    def _update_css(self, color: str):
        self.setStyleSheet(f"""
            QPushButton {{
                background:{color}; color:white; border:none;
                border-radius:{self._radius}px; padding:9px 24px;
                font-weight:600; letter-spacing:0.3px;
            }}
            QPushButton:disabled {{background:#4e586e;}}
        """)
    
    def enterEvent(self, _: QEvent):
        self._update_css(self._hover)
        r = self.geometry()
        r.adjust(-2, -2, 2, 2)
        self._animate(r)
    
    def leaveEvent(self, _: QEvent):
        self._update_css(self._base)
        r = self.geometry().adjusted(2, 2, -2, -2)
        self._animate(r)
    
    def _animate(self, rect):
        self._anim.stop()
        self._anim.setStartValue(self.geometry())
        self._anim.setEndValue(rect)
        self._anim.start()

class GradientHeader(QFrame):
    """Header com gradiente (visual antigo)."""
    def paintEvent(self, evt):
        painter = QPainter(self)
        g = QLinearGradient(QPoint(0, 0), QPoint(self.width(), 0))
        g.setColorAt(0, QColor("#667eea"))
        g.setColorAt(1, QColor("#764ba2"))
        painter.fillRect(self.rect(), QBrush(g))

# ------------------------------------------------------------------------------------------------------------------------------â•â•
#                           WORKER THREAD (Core mantido)
# ------------------------------------------------------------------------------------------------------------------------------â•â•

class CryptoWorker(QThread):
    """Thread worker para operações de criptografia."""
    
    progress = Signal(int, float)  # bytes_done, elapsed_time
    finished = Signal(str)  # output_path
    error = Signal(str)  # error_message
    
    def __init__(
        self,
        operation: str,  # 'encrypt' ou 'decrypt'
        src_path: str,
        password: str,
        delete_flag: bool = False,
        extra_params: Optional[dict] = None,
    ):
        super().__init__()
        self.operation = operation
        self.src_path = src_path
        self.password = password
        self.delete_flag = delete_flag
        self.extra_params = extra_params or {}
        self._start_time = 0
        self._cancelled = False
        # Hold password in SecureBytes to minimize exposure in memory
        self._password_secure = SecureBytes(password.encode() if isinstance(password, str) else password)
    
    def run(self):
        """Executa operação em thread separada."""
        self._start_time = time.time()
        
        try:
            # Callback de progresso
            def progress_callback(bytes_done: int):
                if self._cancelled or self.isInterruptionRequested():
                    raise InterruptedError("Operation cancelled")
                elapsed = time.time() - self._start_time
                self.progress.emit(bytes_done, elapsed)
            
            # Executa operação apropriada
            if self.operation == "encrypt":
                result = self._encrypt(progress_callback, self._password_secure)
            else:
                result = self._decrypt(progress_callback, self._password_secure)
            
            if not self._cancelled:
                self.finished.emit(str(result) if result else "")
                
        except InterruptedError:
            pass
        except Exception as e:
            logger.exception("CryptoWorker error during %s: %s", self.operation, e)
            self.error.emit(str(e))
        finally:
            # Clear password from memory deterministically
            try:
                if hasattr(self, "_password_secure") and self._password_secure is not None:
                    self._password_secure.clear()
            except Exception:
                pass
    
    def _encrypt(self, progress_cb: Callable, password_secure: SecureBytes) -> Path:
        """Executa criptografia."""
        src = Path(self.src_path)
        out_path = self.extra_params.get("out_path", src.with_suffix(".cg2"))
        # Route via v5 factories; fixed algorithm, pass kdf profile and padding

        try:
            return Path(cg_encrypt(
                in_path=str(src),
                password=bytes(password_secure.view()),
                algo="XC20",  # ignored; v5 fixed
                out_path=str(out_path),
                progress_cb=progress_cb,
                kdf_profile=self.extra_params.get("kdf_profile", "INTERACTIVE"),
                padding=self.extra_params.get("padding", "off"),
                keyfile=self.extra_params.get("keyfile"),
                hide_filename=self.extra_params.get("hide_filename", False),
            ))
        except TypeError as e:
            # Erro comum quando a instalação do PyNaCl/libsodium estÃ¡ quebrada ou
            # houve mudança de assinatura inesperada.
            msg = str(e)
            if (
                "crypto_secretstream_xchacha20poly1305_init_push" in msg and
                "missing 1 required positional argument" in msg
            ):
                raise RuntimeError(
                    "SecretStream init failed: PyNaCl/libsodium mismatch.\n"
                    "Fix with:\n  pip install --force-reinstall pynacl\n"
                    "If on Windows, ensure a recent libsodium is available."
                ) from e
            raise
    
    def _decrypt(self, progress_cb: Callable, password_secure: SecureBytes) -> Path:
        """Executa descriptografia."""
        src = Path(self.src_path)
        out_path = self.extra_params.get("out_path", src.with_suffix(""))
        
        result = cg_decrypt(
            in_path=str(src),
            password=bytes(password_secure.view()),
            out_path=str(out_path),
            verify_only=False,
            progress_cb=progress_cb,
            keyfile=self.extra_params.get("keyfile"),
        )
        
        return Path(result) if result else Path("")
    
    def cancel(self):
        """Cancela operação."""
        self._cancelled = True
        self.requestInterruption()

# ------------------------------------------------------------------------------------------------------------------------------â•â•
#                        MAIN WINDOW (Interface Antiga)
# ------------------------------------------------------------------------------------------------------------------------------â•â•

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptGuardv2 - secure")
        # Ajuste de tamanho da janela para 1920×1080 @125%
        self.setMinimumSize(QSize(1100, 700))
        self.resize(QSize(1100, 700))
        
        # Aplica paleta antiga PRIMEIRO
        self._apply_palette_old_theme()
        
        # Estado
        self.vm: Optional[VaultManager] = None
        self.worker: Optional[CryptoWorker] = None
        self._temp_files: list[Path] = []
        self._original_path = ""
        self._tmp_zip = None
        self._forced_out = ""
        self._is_encrypt = False
        # Simple rate limiting (per file path)
        self._failed_attempts = {}
        self._lockout_until = {}
        
        # Constrói UI
        self._build_ui()

        # Garantir KeyGuard apos montar a UI (próximo ciclo do event loop)
        QTimer.singleShot(0, self._ensure_keyguard)
        self.setAcceptDrops(True)

    # ----------------------------- tema/paleta (faltante) -----------------------------
    def _apply_palette_old_theme(self) -> None:
        """
        Define paleta dark + CSS base (estilo clássico do app).
        """
        app = QApplication.instance()
        if app is None:
            return

        pal = QPalette()
        pal.setColor(QPalette.Window, QColor("#1b212b"))
        pal.setColor(QPalette.WindowText, QColor("#e6eaf0"))
        pal.setColor(QPalette.Base, QColor("#202734"))
        pal.setColor(QPalette.AlternateBase, QColor("#283244"))
        pal.setColor(QPalette.Text, QColor("#e6eaf0"))
        pal.setColor(QPalette.ToolTipBase, QColor("#2b3342"))
        pal.setColor(QPalette.ToolTipText, QColor("#e6eaf0"))
        pal.setColor(QPalette.Button, QColor("#303a4b"))
        pal.setColor(QPalette.ButtonText, QColor("#e6eaf0"))
        pal.setColor(QPalette.Highlight, QColor("#536dfe"))
        pal.setColor(QPalette.HighlightedText, QColor("#ffffff"))
        with contextlib.suppress(Exception):
            pal.setColor(QPalette.PlaceholderText, QColor(230, 234, 240, 120))
        app.setPalette(pal)

        app.setStyleSheet("""
            QWidget { background: #1b212b; color: #e6eaf0; }
            QLabel  { color: #e6eaf0; }
            QLineEdit, QPlainTextEdit, QTextEdit {
                background: #2a3342; color: #e6eaf0;
                border: 1px solid #3a4356; border-radius: 6px; padding: 4px;
            }
            QComboBox {
                background: #2a3342; color: #e6eaf0;
                border: 1px solid #3a4356; border-radius: 6px; padding: 4px 8px;
            }
            QComboBox QAbstractItemView {
                background: #2a3342; color: #e6eaf0;
                selection-background-color: #536dfe;
            }
            QPushButton {
                background: #536dfe; color: #ffffff;
                border: none; border-radius: 6px; padding: 6px 12px;
            }
            QPushButton:disabled { background: #4e586e; }
            QCheckBox { padding: 0px 2px; margin: 0; }
            QProgressBar {
                background: #1f2633; color: #e6eaf0; height: 12px;
                border: 1px solid #3a4356; border-radius: 4px;
                text-align: center;
            }
            QProgressBar::chunk { background: #536dfe; }
            QStatusBar { background: #151a22; color: #9aa3b2; }
            QToolTip { background: #2b3342; color: #e6eaf0; border: 1px solid #3a4356; }
        """)
    # --- KeyGuard integration (centralizado) ------------------------------
    def _ensure_keyguard(self) -> None:
        """Anexa o KeyGuard (Qt) no lado direito (com fallback de import) uma única vez."""
        # Se ainda não temos helper, tenta novamente o fallback dinâmico.
        global attach_keyguard_qt
        if attach_keyguard_qt is None:
            try:
                import importlib.util, pathlib
                _BASE = pathlib.Path(__file__).resolve().parent
                for _cand in (
                    _BASE / "modules" / "keyguard" / "qt_pane.py",
                    _BASE / "qt_pane.py",
                ):
                    if _cand.exists():
                        _spec = importlib.util.spec_from_file_location("keyguard_qt_pane", _cand)
                        _mod = importlib.util.module_from_spec(_spec)  # type: ignore
                        assert _spec and _spec.loader
                        _spec.loader.exec_module(_mod)                 # type: ignore
                        attach_keyguard_qt = getattr(_mod, "attach_keyguard_qt", None)
                        if attach_keyguard_qt:
                            break
            except Exception as e:
                logger.exception("Falha ao importar KeyGuard: %s", e)
                attach_keyguard_qt = None
        if attach_keyguard_qt is None:
            # Reporta para você saber o motivo caso o painel não apareça.
            if hasattr(self, "status_bar"):
                self.status_bar.showMessage("KeyGuard module not found (import failed).", 6000)
            return
        body = getattr(self, "body_layout", None)
        if body is None:
            return
        # já anexado?
        if getattr(self, "keyguard_pane", None):
            return
        try:
            sep = QFrame()
            sep.setFrameShape(QFrame.VLine)
            sep.setStyleSheet("color:#1b202a;")
            self.body_layout.addWidget(sep, 0)
            pane = attach_keyguard_qt(self, width=380)
            if pane:
                try:
                    pane.setMinimumWidth(380)
                except Exception as e:
                    logger.exception("Erro ao configurar KeyGuard pane: %s", e)
                    pass
                self.keyguard_pane = pane
                if hasattr(self, "status_bar"):
                    self.status_bar.showMessage("KeyGuard loaded.", 2500)
        except Exception as e:
            with contextlib.suppress(Exception):
                logger.exception("KeyGuard sidebar unavailable: %s", e)
        # Cria label_status para compatibilidade (não visÃ­vel)
        self.label_status = QLabel()
        self.label_time = QLabel()
        
        # OPCIONAL: Cria aliases para compatibilidade total com código antigo
        self._create_aliases()
    
    def _create_aliases(self):
        """Cria aliases para compatibilidade com nomes antigos."""
        self.file_line = self.file_input
        self.cmb_alg = None
        self.cmb_prof = self.combo_profile
        self.cmb_pad = self.combo_padding
        self.pwd = self.password_input
        self.str_bar = self.strength_bar
        self.chk_exp = self.check_expiration
        self.date_exp = self.date_expiration
        self.chk_del = self.check_delete
        self.chk_archive = self.check_archive
        self.chk_vault = self.check_vault
        self.prg = self.progress_bar
        self.lbl_speed = self.label_speed
        self.status = self.status_bar
        self.btn_enc = self.btn_encrypt
        self.btn_dec = self.btn_decrypt

    def apply_generated_password(self, pwd: str):
        """Allow KeyGuard pane to paste password into main module."""
        try:
            self.password_input.setText(pwd)
        except Exception:
            pass
    
    def _field(self, label: str, widget):
        """Helper da UI antiga para alinhar label + widget."""
        lab = QLabel(label)
        lab.setFont(QFont("Inter", 10, QFont.Bold))
        lay = QHBoxLayout()
        lay.addWidget(lab)
        lay.addWidget(widget)
        lay.addStretch()
        return lay
    
    def _combo(self, items):
        """Helper para criar combo estilizado."""
        cmb = QComboBox()
        cmb.addItems(items)
        cmb.setMaximumWidth(280)
        cmb.setStyleSheet(
            "QComboBox{background:#37474F;color:#ECEFF1;border:1px solid #455A64;"
            "border-radius:5px;padding:5px 10px;}"
            "QComboBox::drop-down{border:none;}"
            "QComboBox QAbstractItemView{background:#37474F;selection-background-color:#546E7A;color:white;}"
        )
        return cmb
    
    def _update_password_strength(self, txt: str):
        """Atualiza indicador de força da senha."""
        try:
            from zxcvbn import zxcvbn
            score = zxcvbn(txt)["score"] if txt else 0
        except Exception:
            # Fallback simples
            score = 0
            if len(txt) >= 8:
                score += 1
            if any(c.isupper() for c in txt):
                score += 1
            if any(c.isdigit() for c in txt):
                score += 1
            if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in txt):
                score += 1
        
        # Converter score de 0-4 para 0-100
        strength_value = (score * 25) if score > 0 else 0
        self.strength_bar.setValue(strength_value)
        colors = ["#d32f2f", "#f57c00", "#fbc02d", "#43a047", "#1b5e20"]
        self.strength_bar.setStyleSheet(f"QProgressBar::chunk{{background:{colors[min(score, 4)]};}}") 
    
    # ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------â”€
    #                           EVENT HANDLERS
    # ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------â”€
    
    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
    
    def dropEvent(self, e: QDropEvent):
        urls = e.mimeData().urls()
        if not urls:
            return
        path = Path(urls[0].toLocalFile())
        if path.exists():
            self.file_input.setText(str(path))
            self._detect_algo(str(path))
            if path.is_dir():
                self.status_bar.showMessage(f"Folder loaded via drag & drop: {path.name}")
                if not self.check_archive.isChecked():
                    self.check_archive.setChecked(True)
            else:
                file_type = "CG2" if is_cg2_file(path) else "file"
                self.status_bar.showMessage(f"{file_type} loaded via drag & drop: {path.name}")
    
    def _detect_algo(self, path: str):
        """Detect CG2 version (v1–v4 legacy or v5) and update status."""
        try:
            src = Path(path)
            if not src.exists() or src.is_dir():
                return
            from crypto_core.fileformat_v5 import read_header_version_any
            try:
                ver = read_header_version_any(src)
            except Exception:
                return  # not a CG2 file; stay silent
            if ver >= 5:
                self.status_bar.showMessage("Detected CG2 v5")
            else:
                self.status_bar.showMessage("Legacy CG2 format (read-only)")
        except Exception as e:
            self.status_bar.showMessage(f"Could not detect format: {e}")
    
    # ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------â”€
    #                               SLOTS
    # ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------â”€
    
    def _browse_file(self):
        """Abre diÃ¡logo para selecionar arquivo/pasta."""
        msg = QMessageBox(self)
        msg.setWindowTitle("Select type")
        msg.setText("Choose what you want to encrypt / decrypt:")
        file_btn = msg.addButton("File", QMessageBox.AcceptRole)
        msg.addButton("Folder", QMessageBox.AcceptRole)
        msg.addButton(QMessageBox.Cancel)
        msg.exec()
        clicked = msg.clickedButton()
        
        if clicked is None or clicked == msg.button(QMessageBox.Cancel):
            return
        
        if clicked == file_btn:
            f, _ = QFileDialog.getOpenFileName(self, "Choose file")
            if f:
                self.file_input.setText(f)
                self._detect_algo(f)
                self.status_bar.showMessage("File selected.")
        else:
            folder = QFileDialog.getExistingDirectory(self, "Choose folder")
            if folder:
                self.file_input.setText(folder)
                self._detect_algo(folder)
                self.status_bar.showMessage("Folder selected.")
                if not self.check_archive.isChecked():
                    self.check_archive.setChecked(True)
    
    def _browse_keyfile(self):
        """Select keyfile path for 2FA."""
        f, _ = QFileDialog.getOpenFileName(self, "Choose keyfile")
        if f:
            self.keyfile_input.setText(f)
            self.status_bar.showMessage("Keyfile selected.")

    def _toggle_password_visibility(self, checked: bool):
        """Alterna visibilidade da senha com rotulos ASCII (evita mojibake)."""
        self.password_input.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        try:
            self.btn_show_password.setText("Hide" if checked else "Show")
        except Exception:
            pass
    def _start_operation(self, operation: str):
        """Inicia operação de criptografia/descriptografia."""
        try:
            path = self.file_input.text().strip()
            if not path:
                self.status_bar.showMessage("Select a file first.")
                return
            pwd = self.password_input.text()
            if not pwd:
                self.status_bar.showMessage("Enter a password.")
                return

            self._is_encrypt = (operation == "encrypt")

            self._original_path = path
            src = path
            self._tmp_zip = None
            self._forced_out = ""
            src_path = Path(src)

            if src_path.is_dir():
                if not self._is_encrypt:
                    QMessageBox.warning(self, "Invalid Selection", "Please select a file for decrypt/verify.")
                    self.status_bar.showMessage("Select a file for decrypt/verify.")
                    return
                if not self.check_archive.isChecked():
                    QMessageBox.information(
                        self,
                        "Auto-Archive",
                        "Folders require ZIP archiving for encryption. Enabling automatically."
                    )
                    self.check_archive.setChecked(True)

            if self._is_encrypt and self.check_archive.isChecked() and src_path.is_dir():
                try:
                    tmp_zip = archive_folder(src)
                    self._tmp_zip = tmp_zip
                    src = str(tmp_zip)
                    self._forced_out = str(Path(self.file_input.text()).with_suffix(".cg2"))
                    self._operation_size = Path(tmp_zip).stat().st_size
                except Exception as e:
                    self.status_bar.showMessage(f"Zip error: {e}")
                    return

            try:
                src_size = Path(src).stat().st_size
            except Exception as e:
                if self._tmp_zip:
                    with contextlib.suppress(Exception):
                        os.remove(self._tmp_zip)
                self.status_bar.showMessage(f"Source access error: {e}")
                return

            alg_name = "XChaCha20-Poly1305 (SecretStream)"
            kdf_profile = "INTERACTIVE" if self.combo_profile.currentText().lower().startswith("inter") else "SENSITIVE"

            if self._is_encrypt:
                self.status_bar.showMessage(f"Encrypting with {alg_name}")
            else:
                try:
                    from crypto_core.fileformat_v5 import read_header_version_any
                    ver = read_header_version_any(src)
                    self.status_bar.showMessage(
                        "Decrypting CG2 v5 (SecretStream)" if ver >= 5 else "Decrypting legacy CG2"
                    )
                except Exception:
                    self.status_bar.showMessage("Decrypting (unknown format)")

            delete_flag = self.check_delete.isChecked()
            extra: dict[str, Any] = {}

            # Optional keyfile for both encrypt/decrypt
            if self.check_keyfile.isChecked() and self.keyfile_input.text().strip():
                extra["keyfile"] = self.keyfile_input.text().strip()

            if self._is_encrypt and self.check_expiration.isChecked():
                qd = self.date_expiration.date()
                exp_dt = datetime(qd.year(), qd.month(), qd.day(), tzinfo=UTC)
                if exp_dt.date() < datetime.now(UTC).date():
                    self.status_bar.showMessage("Expiration date cannot be in the past.")
                    return
                extra["expires_at"] = int(exp_dt.timestamp())

            if self._is_encrypt:
                pad_name = self.combo_padding.currentText().lower().replace(" ", "")
                pad_map = {"off": "off", "4kb": "4k", "16kb": "16k"}
                extra["padding"] = pad_map.get(pad_name, "off")
                extra["kdf_profile"] = kdf_profile
                extra["out_path"] = self._forced_out or str(Path(src).with_suffix(".cg2"))
                extra["hide_filename"] = self.check_hide_filename.isChecked()

            if not hasattr(self, "_operation_size"):
                self._operation_size = src_size

            # Disable UI & prepare progress
            self._toggle(False)
            self.progress_bar.setMaximum(0)
            self.progress_bar.setValue(0)
            self.status_bar.showMessage("Deriving key (Argon2)…")

            self.worker = CryptoWorker(
                operation,
                src,
                pwd,
                delete_flag,
                extra
            )
            self.worker.progress.connect(self._update_progress)
            self.worker.finished.connect(self._operation_finished)
            self.worker.error.connect(self._operation_error)
            self.worker.start()
            self.password_input.clear()
        except Exception as ex:
            logger.exception("start_operation failure")
            QMessageBox.critical(self, "Erro", f"Falha ao iniciar: {ex}")
            self.status_bar.showMessage(f"Erro ao iniciar: {ex}", 10000)
            self._toggle(True)

    def _verify_file(self):
        """Verifica integridade de arquivo criptografado."""
        path = self.file_input.text()
        pwd = self.password_input.text()
        
        if not path or not pwd:
            return self.status_bar.showMessage("Select file and enter password.")
        
        try:
            kf = self.keyfile_input.text().strip() if self.check_keyfile.isChecked() else None
            if verify_integrity(path, pwd, keyfile=kf):
                QMessageBox.information(self, "Verify", "Integridade OK.")
            else:
                raise ValueError("Integridade falhou.")
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Verificação falhou: {str(e)}")
        
        # Note: on failure we increment attempt counters above and may lock out further attempts
        self.password_input.clear()
    
    def _cancel_operation(self):
        """Cancela operação em andamento."""
        if hasattr(self, "worker") and self.worker and self.worker.isRunning():
            self.worker.cancel()
            if not self.worker.wait(5000):
                timer = QTimer(self)
                timer.timeout.connect(self.worker.quit)
                timer.start(100)
                self.worker.wait(1000)
            
            self.status_bar.showMessage("Operation cancelled.", 5000)
            self.btn_cancel.setEnabled(False)
            self._toggle(True)
            
            if self._tmp_zip:
                with contextlib.suppress(Exception):
                    os.remove(self._tmp_zip)
            
            # Worker handles cleanup internally; just signal finish
            self.worker.finished.emit("")
    
    def _toggle(self, enabled: bool):
        """Habilita/desabilita controles."""
        for w in (
            self.btn_encrypt,
            self.btn_decrypt,
            self.btn_verify,
            self.combo_profile,
            self.combo_padding,
            self.password_input,
            self.check_keyfile,
            self.keyfile_input,
            self.btn_pick_keyfile,
            self.check_hide_filename,
            self.check_delete,
            self.check_archive,
            self.check_vault,
            self.check_extract,
            self.check_expiration,
            self.date_expiration,
        ):
            w.setEnabled(enabled)
        
        if enabled:
            self.btn_cancel.setEnabled(False)
            self.progress_bar.setMaximum(100)
            self.label_speed.setText("Speed: - MB/s")
            if hasattr(self, "worker"):
                del self.worker
        else:
            self.btn_cancel.setEnabled(True)
    
    def _update_progress(self, bytes_done: int, elapsed: float):
        """Atualiza progresso da operação."""
        if self.progress_bar.maximum() == 0:
            self.progress_bar.setMaximum(100)
        
        # Usa _operation_size se existir (foi setado para ZIP)
        total = getattr(self, "_operation_size", 0)
        
        if total:
            pct = min(int(bytes_done * 100 / total), 100)
            self.progress_bar.setValue(pct)
        
        speed = human_speed(bytes_done, elapsed)
        self.label_speed.setText(f"Speed: {speed}")
    
    def _operation_finished(self, out_path: str):
        """operação concluída com sucesso."""
        if not out_path:
            self.status_bar.showMessage("Operation cancelled.", 5000)
            self._toggle(True)
            return
        
        self.progress_bar.setValue(100)
        
        # Limpa ZIP temporÃ¡rio
        if hasattr(self, "_tmp_zip") and self._tmp_zip:
            Path(self._tmp_zip).unlink(missing_ok=True)
        
        final_output = out_path
        
        # PATCH 7.2: Extração automÃ¡tica pós-decrypt
        if not self._is_encrypt and self.check_extract.isChecked() and out_path.endswith(".zip"):
            if zipfile.is_zipfile(out_path):
                dest_dir = Path(out_path).with_suffix("")
                try:
                    with zipfile.ZipFile(out_path, "r") as zf:
                        zf.extractall(dest_dir)
                    Path(out_path).unlink(missing_ok=True)
                    final_output = str(dest_dir)
                    self.status_bar.showMessage(f"Extracted to: {dest_dir}", 5000)
                except Exception as e:
                    logger.warning(f"Auto-extract failed: {e}")
                    QMessageBox.warning(self, "Extract", f"Could not extract ZIP: {e}")
        
        # Vault (opcional)
        if self._is_encrypt and self.check_vault.isChecked():
            try:
                if self.vm is None:
                    self._open_vault()
                    if self.vm is None:
                        raise RuntimeError("Vault not opened")
                
                self.vm.add_file(final_output)
                Path(final_output).unlink(missing_ok=True)
                self.status_bar.showMessage("File moved to Vault.", 8000)
                QMessageBox.information(
                    self,
                    "Success",
                    "File encrypted and moved to Vault successfully."
                )
            except Exception as e:
                QMessageBox.warning(
                    self,
                    "Vault",
                    f"Could not store file in Vault:\n{e}"
                )
                QMessageBox.information(
                    self,
                    "Success",
                    f"Output file:\n{Path(final_output).name}"
                )
        else:
            QMessageBox.information(
                self,
                "Success",
                f"Output file:\n{Path(final_output).name}"
            )
        
        # Secure-delete
        if self.check_delete.isChecked():
            try:
                p = Path(self._original_path)
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    secure_delete(self._original_path, passes=1)
            except Exception as e:
                self.status_bar.showMessage(f"Delete failed: {e}", 8000)
        
        self.status_bar.showMessage("Done.", 8000)
        
        # Limpa _operation_size
        if hasattr(self, "_operation_size"):
            delattr(self, "_operation_size")
        
        self._toggle(True)
    
    def _operation_error(self, msg: str):
        """Erro na operação."""
        # Rate limiting tracking for failed decrypts
        try:
            if not self._is_encrypt:
                path_key = self._original_path
                self._failed_attempts[path_key] = self._failed_attempts.get(path_key, 0) + 1
                if self._failed_attempts[path_key] >= 5:
                    self._lockout_until[path_key] = time.time() + 300
        except Exception:
            pass
        if getattr(self, "_tmp_zip", None):
            with contextlib.suppress(Exception):
                os.remove(self._tmp_zip)
        
        # Traduz erros comuns
        if "InvalidTag" in msg or "MAC check failed" in msg:
            msg = "Senha ou arquivo incorretos."
        elif "expired" in msg.lower():
            msg = "Arquivo expirado, não pode ser descriptografado."
        if "PyNaCl/libsodium mismatch" in msg or "SecretStream init failed" in msg or "SecretStream API mismatch" in msg:
            msg += "\nSugestão: pip install -U --force-reinstall 'pynacl>=1.5.0'"
        
        QMessageBox.critical(self, "Erro", msg)
        self.status_bar.showMessage(f"Error: {msg}", 10000)
        
        # Limpa _operation_size
        if hasattr(self, "_operation_size"):
            delattr(self, "_operation_size")
        
        self._toggle(True)
    
    # --- MOVIDO PARA CIMA & TORNADO NÃƒO BLOQUEANTE ---
    def _secretstream_preflight(self, silent: bool = False) -> tuple[bool, str]:
        """
        Verifica se a API crypto_secretstream_xchacha20poly1305_init_push tem a
        assinatura esperada (1 arg: key). Em versÃµes legadas pode exigir 2 args
        (header, key) ou outra forma â€“ não suportada pelo xchacha_stream atual.
        Retorna (ok, mensagem_de_erro_ou_vazia).
        """
        try:
            import inspect, nacl
            from nacl import bindings as nb
            func = nb.crypto_secretstream_xchacha20poly1305_init_push
            sig = inspect.signature(func)
            # Assinatura moderna: (key: bytes) -> (state, header)
            if len(sig.parameters) == 1:
                # Teste rÃ¡pido
                try:
                    func(b"\x00" * 32)
                except Exception:
                    # Pode falhar por key não aleatória, ignoramos se TypeError não ocorre.
                    pass
                return True, ""
            # Assinatura legada ou inesperada
            msg = (
                f"Incompatible SecretStream API (expected 1 param, got {len(sig.parameters)}). "
                f"PyNaCl version: {getattr(nacl, '__version__', '?')}. "
                "Upgrade with: pip install -U --force-reinstall 'pynacl>=1.5.0'"
            )
            if not silent:
                QMessageBox.critical(self, "SecretStream API", msg)
            return False, msg
        except Exception as e:
            return False, f"SecretStream preflight failed: {e}"

    def _open_vault(self):
        """Abre (ou cria) o Vault e mostra o diÃ¡logo de seleção de arquivo."""
        while True:
            pw, ok = QInputDialog.getText(
                self,
                "Vault Password",
                "Digite a senha do Vault:",
                QLineEdit.Password
            )
            if not ok or not pw:
                return
            try:
                vault_path = Config.default_vault_path()
                if vault_path.exists() and vault_path.stat().st_size == 0:
                    vault_path.unlink()
                exists = vault_path.exists()
                if not exists:
                    # Confirmar criação explícita para evitar criar com senha errada por engano
                    if QMessageBox.question(
                        self,
                        "Criar Vault",
                        f"Nenhum vault encontrado em:\n{vault_path}\n\nDeseja criar um novo?",
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No,
                    ) != QMessageBox.Yes:
                        return
                    if USING_V2:
                        vm = VaultManager(AtomicStorageBackend(vault_path))
                    else:
                        class SimpleBackend:
                            def __init__(self, path):
                                self.path = Path(path)
                                self.path.parent.mkdir(parents=True, exist_ok=True)
                            def save(self, data: bytes):
                                self.path.write_bytes(data)
                            def load(self) -> bytes:
                                return self.path.read_bytes() if self.path.exists() else b""
                        vm = VaultManager(storage=SimpleBackend(vault_path))
                    vm.create(pw)
                    self.vm = vm
                    self.status_bar.showMessage("Novo Vault criado com sucesso.", 8000)
                else:
                    # Abre vault existente (não cria automaticamente aqui)
                    if USING_V2:
                        vm = VaultManager(AtomicStorageBackend(vault_path))
                        vm.open(pw)
                        self.vm = vm
                    else:
                        self.vm = open_or_init_vault(pw, vault_path)
                    self.status_bar.showMessage("Vault aberto com sucesso.", 8000)
            except CorruptVault:
                if QMessageBox.question(
                    self,
                    "Vault corrompido",
                    "O arquivo vault3.dat parece corrompido.\nDeseja sobrescrevÃª-lo?",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No,
                ) == QMessageBox.Yes:
                    vault_path.unlink(missing_ok=True)
                    continue
                else:
                    return
            except WrongPassword as e:
                logger.vault_error("open", "CryptGuard", e, {
                    "vault_path": str(vault_path),
                    "ui_context": "main_app_open_vault"
                })
                QMessageBox.warning(self, "Vault", "Senha do Vault incorreta. Tente novamente.")
                continue
            except VaultLocked as e:
                QMessageBox.warning(self, "Vault Bloqueado", str(e))
                return
            finally:
                pw = ""
            break

        if self.vm is not None:
            dlg = VaultDialog(self.vm, self)
            dlg.file_selected.connect(
                lambda p: (
                    self.file_input.setText(p),
                    self._detect_algo(p),
                    self.status_bar.showMessage("File selected from Vault."),
                )
            )
            dlg.exec()

    def _change_vault_password(self):
        """Altera senha do vault."""
        if self.vm is None:
            QMessageBox.information(self, "Vault", "Abra um Vault primeiro.")
            return
        
        old_pw, ok = QInputDialog.getText(
            self,
            "Senha atual",
            "Digite a senha atual:",
            QLineEdit.Password
        )
        if not ok or not old_pw:
            return
        
        new_pw, ok2 = QInputDialog.getText(
            self,
            "Nova senha",
            "Digite a nova senha:",
            QLineEdit.Password
        )
        if not ok2 or not new_pw:
            return
        
        confirm, ok3 = QInputDialog.getText(
            self,
            "Confirme a nova senha",
            "Repita a nova senha:",
            QLineEdit.Password
        )
        if not ok3 or new_pw != confirm:
            QMessageBox.warning(self, "Erro", "As senhas não coincidem.")
            return
        
        try:
            # Passa strings; o Vault converte de forma segura internamente
            self.vm.change_password(old_pw, new_pw)
            QMessageBox.information(self, "Sucesso", "Senha do Vault alterada com sucesso.")
        except WrongPassword:
            logger.warning("Vault: tentativa de troca com senha atual incorreta")
            QMessageBox.critical(self, "Senha incorreta", "A senha atual está incorreta.")
        except Exception as e:
            logger.exception("Vault: erro ao trocar senha: %s", e)
            QMessageBox.critical(self, "Erro", str(e))
        finally:
            old_pw = new_pw = confirm = ""
    
    def _show_settings(self):
        """Mostra diÃ¡logo de configuraçÃµes (paridade com main_app.py)."""
        QMessageBox.information(self, "Settings", "Settings dialog not yet implemented.")


    def _open_log(self):
        """Abre o arquivo de log no editor padrão."""
        try:
            for h in getattr(logger, "handlers", []):
                with contextlib.suppress(Exception):
                    h.flush()
            
            try:
                LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
                LOG_PATH.touch(exist_ok=True)
            except Exception:
                pass
            
            # Qt
            if QDesktopServices.openUrl(QUrl.fromLocalFile(str(LOG_PATH))):
                return
            
            # Windows
            if sys.platform.startswith("win"):
                try:
                    os.startfile(str(LOG_PATH))
                    return
                except Exception:
                    pass
            
            # Unix
            for cmd in ("xdg-open", "open"):
                try:
                    import subprocess
                    subprocess.Popen([cmd, str(LOG_PATH)])
                    return
                except Exception:
                    continue
            
            QMessageBox.information(self, "Log", f"Log file:\n{LOG_PATH}")
        except Exception as e:
            QMessageBox.warning(
                self,
                "Log",
                f"Não foi possÃ­vel abrir o log:\n{e}\n\nCaminho: {LOG_PATH}"
            )
    def _show_about(self):
        """Mostra diÃ¡logo Sobre (paridade com main_app.py)."""
        ver = getattr(self, "APP_VERSION", "3.0")
        QMessageBox.about(
            self,
            "Sobre o CryptGuardv2",
            (
                "<h3>CryptGuardv2</h3>"
                f"<p>Versão {ver}</p>"
                "<p>Criptografia de arquivos e pastas com arquitetura moderna e auditÃ¡vel.</p>"
                "<p><b>Destaques:</b></p>"
                "<ul>"
                "<li><b>Container v5</b> com AAD ligada ao cabeçalho e JSON canÃ´nico</li>"
                "<li>Streaming <b>XChaCha20-Poly1305</b> (libsodium SecretStream)</li>"
                "<li><b>Argon2id</b> com perfis por alvo de tempo</li>"
                "<li>Escrita atÃ´mica e segura contra panes (tmp + fsync no diretório)</li>"
                "<li><b>Padding</b> opcional para ofuscar tamanhos</li>"
                "<li>Suporte a <b>senha + keyfile</b></li>"
                "<li><b>Vault</b> para gerenciar itens criptografados</li>"
                "<li>Logs com redação; verificação sem deixar plaintext</li>"
                "</ul>"
                "<p>Â© 2024â€“2025 CryptGuard Team</p>"
            ),
        )

    def _show_help(self):
        """Mostra diálogo de ajuda (paridade com main_app.py)."""
        QMessageBox.information(
            self,
            "Ajuda",
            (
                "<h3>Como usar o CryptGuardv2 (formato v5)</h3>"
                "<p><b>Criptografar:</b></p>"
                "<ol>"
                "<li>Selecione um arquivo ou pasta (arraste & solte ou <i>Selecionar…</i>).</li>"
                "<li>Em <b>Opções</b>, defina:<br>"
                " &nbsp;• <b>Perfil KDF</b>: <i>Interactive</i> (~350 ms) ou <i>Sensitive</i> (~700 ms)<br>"
                " &nbsp;• <b>Padding</b>: off / 4k / 16k (oculta o tamanho exato)<br>"
                " &nbsp;• <b>Ocultar nome do arquivo</b> (restaura só a extensão)<br>"
                " &nbsp;• <b>Keyfile</b> (opcional, 2º fator)"
                "</li>"
                "<li>Digite uma senha forte (12+ caracteres ou frase longa).</li>"
                "<li>Clique em <b>Criptografar</b>.</li>"
                "</ol>"
                "<p><b>Descriptografar:</b></p>"
                "<ol>"
                "<li>Selecione um arquivo <code>.cg2</code>.</li>"
                "<li>Informe a senha (e o keyfile, se usado).</li>"
                "<li>Clique em <b>Descriptografar</b>.</li>"
                "</ol>"
                "<p><b>Dicas e notas:</b></p>"
                "<ul>"
                "<li>AEAD em streaming (<i>XChaCha20-Poly1305 SecretStream</i>) impede truncamento/reordenação.</li>"
                "<li>Padding oculta o tamanho; a decifragem volta ao tamanho original.</li>"
                "<li>Escritas são atômicas (tmp + fsync). Sem deixar plaintext em falhas de autenticação.</li>"
                "<li>Senhas/keyfiles perdidos não podem ser recuperados.</li>"
                "<li>Use o <b>Vault</b> para organizar itens criptografados.</li>"
                "</ul>"
            ),
        )

    def _compact(self, layout, spacing=4):
        """Remove margens padrão e reduz o espaço entre itens do layout."""
        try:
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(spacing)
        except Exception:
            pass

    # Builder compatível com a UI clássica (sem mudar layout/nomes de widgets).
    # Se existir um builder legado, usamos ele; do contrário, montamos a UI
    # mínima com os mesmos ids que o restante do código espera.
    def _build_ui(self) -> None:
        for name in ("build_ui", "_build_main_ui", "_build_ui_v2", "_build_ui_old"):
            if hasattr(self, name):
                getattr(self, name)()
                return

        # --------- Fallback: monta a UI esperada pelo restante do código ---------
        root = QVBoxLayout(self)
        # Leve aumento de margens e espaçamento global para "respirar" melhor
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # Área central que o KeyGuard anexa (usada em _ensure_keyguard)
        self.body_layout = QHBoxLayout()
        # Um pouco mais de espaço entre painel esquerdo e o KeyGuard (direita)
        self.body_layout.setSpacing(12)
        root.addLayout(self.body_layout, 1)

        # Painel esquerdo (controles principais)
        left = QFrame(self)
        left.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)  # ocupa altura total
        lv = QVBoxLayout(left)
        # Margens e espaçamento maiores para distribuir melhor os controles
        lv.setContentsMargins(10, 12, 10, 12)
        lv.setSpacing(10)

        # Linha: arquivo + Select…
        self.file_input = QLineEdit(self)
        self.file_input.setPlaceholderText("Drop a file or click Select…")
        self.btn_select = QPushButton("Select…", self)
        self.btn_select.clicked.connect(self._browse_file)
        row = QHBoxLayout(); self._compact(row, 8)
        row.addWidget(self.file_input, 1)
        row.addWidget(self.btn_select)
        lv.addLayout(row)
        # respiro entre seletor de arquivo e seção seguinte
        lv.addSpacing(6)

        # Algorithm (label estático, como na UI clássica)
        alg_label = QLabel("Algorithm    XChaCha20-Poly1305 (SecretStream)", self)
        alg_label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        lv.addWidget(alg_label)
        lv.addSpacing(6)

        # KDF profile - modernizado
        kdf_row = QHBoxLayout(); self._compact(kdf_row, 8)
        kdf_label = QLabel("KDF profile", self)
        kdf_label.setStyleSheet("font-weight: 600; color: #e6eaf0;")
        kdf_label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        kdf_row.addWidget(kdf_label)
        self.combo_profile = QComboBox(self)
        self.combo_profile.addItems(["Interactive", "Sensitive"])
        self.combo_profile.setMaximumWidth(160)
        self.combo_profile.setStyleSheet("""
            QComboBox {
                background: #37474F; color: #e6eaf0;
                border: 1px solid #546e7a; border-radius: 6px;
                padding: 4px 8px; font-weight: 500;
                selection-background-color: #536dfe;
            }
            QComboBox:hover {
                border: 1px solid #536dfe;
                background: #3a4b57;
            }
            QComboBox::drop-down {
                border: none; width: 18px;
                subcontrol-origin: padding;
                subcontrol-position: top right;
            }
            QComboBox::down-arrow {
                width: 10px; height: 10px;
                image: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMiAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTMgNUw2IDhMOSA1IiBzdHJva2U9IiNlNmVhZjAiIHN0cm9rZS13aWR0aD0iMS41IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz4KPC9zdmc+);
            }
            QComboBox QAbstractItemView {
                background: #37474F; color: #e6eaf0;
                border: 1px solid #546e7a; border-radius: 6px;
                selection-background-color: #536dfe;
                outline: none;
            }
        """)
        kdf_row.addWidget(self.combo_profile)
        kdf_row.addStretch(1)
        lv.addLayout(kdf_row)
        lv.addSpacing(4)

        # Pad size - modernizado
        pad_row = QHBoxLayout(); self._compact(pad_row, 8)
        pad_label = QLabel("Pad size", self)
        pad_label.setStyleSheet("font-weight: 600; color: #e6eaf0;")
        pad_label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        pad_row.addWidget(pad_label)
        self.combo_padding = QComboBox(self)
        self.combo_padding.addItems(["Off", "4 KB", "16 KB"])  # mapeia para 4k/16k no start_operation
        self.combo_padding.setMaximumWidth(120)
        self.combo_padding.setStyleSheet("""
            QComboBox {
                background: #37474F; color: #e6eaf0;
                border: 1px solid #546e7a; border-radius: 6px;
                padding: 4px 8px; font-weight: 500;
                selection-background-color: #536dfe;
            }
            QComboBox:hover {
                border: 1px solid #536dfe;
                background: #3a4b57;
            }
            QComboBox::drop-down {
                border: none; width: 18px;
                subcontrol-origin: padding;
                subcontrol-position: top right;
            }
            QComboBox::down-arrow {
                width: 10px; height: 10px;
                image: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMiAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTMgNUw2IDhMOSA1IiBzdHJva2U9IiNlNmVhZjAiIHN0cm9rZS13aWR0aD0iMS41IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz4KPC9zdmc+);
            }
            QComboBox QAbstractItemView {
                background: #37474F; color: #e6eaf0;
                border: 1px solid #546e7a; border-radius: 6px;
                selection-background-color: #536dfe;
                outline: none;
            }
        """)
        pad_row.addWidget(self.combo_padding)
        pad_row.addStretch(1)
        lv.addLayout(pad_row)
        lv.addSpacing(4)

        # Expiration date
        exp_row = QHBoxLayout(); self._compact(exp_row, 8)
        exp_date_label = QLabel("Expiration date", self)
        exp_date_label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        exp_row.addWidget(exp_date_label)
        self.date_expiration = ClickableDateEdit(self)
        self.date_expiration.setDate(QDate.currentDate())
        self.date_expiration.setCalendarPopup(True)
        exp_row.addWidget(self.date_expiration)
        self.check_expiration = QCheckBox("Enable expiration date", self)
        exp_row.addWidget(self.check_expiration)
        exp_row.addStretch(1)
        lv.addLayout(exp_row)
        lv.addSpacing(6)

        # Password + Show
        p_row = QHBoxLayout(); self._compact(p_row, 8)
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Password…")
        p_row.addWidget(self.password_input, 1)
        self.btn_show_password = QPushButton("Show", self)
        self.btn_show_password.setCheckable(True)
        self.btn_show_password.toggled.connect(self._toggle_password_visibility)
        p_row.addWidget(self.btn_show_password)
        lv.addLayout(p_row)
        
        # Password strength bar
        self.strength_bar = QProgressBar(self)
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        self.strength_bar.setVisible(True)
        lv.addWidget(self.strength_bar)
        lv.addSpacing(6)
        
        # Connect password input to strength update
        self.password_input.textChanged.connect(self._update_password_strength)

        # Keyfile
        kf_row = QHBoxLayout(); self._compact(kf_row, 8)
        self.check_keyfile = QCheckBox("Use keyfile", self)
        kf_row.addWidget(self.check_keyfile)
        self.keyfile_input = QLineEdit(self)
        self.keyfile_input.setPlaceholderText("Pick a keyfile…")
        kf_row.addWidget(self.keyfile_input, 1)
        self.btn_pick_keyfile = QPushButton("Pick", self)
        self.btn_pick_keyfile.clicked.connect(self._browse_keyfile)
        kf_row.addWidget(self.btn_pick_keyfile)
        lv.addLayout(kf_row)
        lv.addSpacing(4)

        # Opções (mesmos nomes usados no restante do código)
        self.check_hide_filename = QCheckBox("Hide filename (restore only extension)", self)
        self.check_delete = QCheckBox("Secure-delete input after operation", self)
        self.check_archive = QCheckBox("Archive folder before encrypt (ZIP)", self)
        self.check_vault = QCheckBox("Store encrypted file in Vault", self)
        self.check_extract = QCheckBox("Auto-extract ZIP after decrypt", self)
        for cb in (self.check_hide_filename, self.check_delete, self.check_archive, self.check_vault, self.check_extract):
            lv.addWidget(cb)
        # dá mais corpo à coluna de opções antes dos botões
        lv.addSpacing(6)

        # Botões de ação (sem alterar rótulos)
        btn_row = QHBoxLayout(); self._compact(btn_row, 10)
        self.btn_encrypt = QPushButton("Encrypt", self)
        self.btn_decrypt = QPushButton("Decrypt", self)
        self.btn_verify  = QPushButton("Verify", self)
        self.btn_cancel  = QPushButton("Cancel", self)
        self.btn_encrypt.clicked.connect(lambda: self._start_operation("encrypt"))
        self.btn_decrypt.clicked.connect(lambda: self._start_operation("decrypt"))
        self.btn_verify.clicked.connect(self._verify_file)
        self.btn_cancel.clicked.connect(self._cancel_operation)
        for b in (self.btn_encrypt, self.btn_decrypt, self.btn_verify, self.btn_cancel):
            btn_row.addWidget(b)
        lv.addLayout(btn_row)

        # Progresso + velocidade
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(0)
        lv.addWidget(self.progress_bar)
        self.label_speed = QLabel("Speed: - MB/s", self)
        lv.addWidget(self.label_speed)
        # Em vez de um grande "vazio" empurrando o rodapé, usamos um espaçamento leve
        lv.addSpacing(8)

        # --- Rodapé: botões à direita (como na UI antiga) ---
        footer = QHBoxLayout(); self._compact(footer, 10)
        footer.addStretch(1)  # empurra tudo para a direita
        self.btn_log = QPushButton("Log", self)
        self.btn_log.clicked.connect(self._open_log)
        footer.addWidget(self.btn_log)

        self.btn_change_pw = QPushButton("Change Password", self)
        self.btn_change_pw.clicked.connect(self._change_vault_password)
        footer.addWidget(self.btn_change_pw)

        self.btn_vault = QPushButton("Vault", self)
        self.btn_vault.clicked.connect(self._open_vault)
        footer.addWidget(self.btn_vault)

        self.btn_settings = QPushButton("Settings", self)
        self.btn_settings.clicked.connect(self._show_settings)
        footer.addWidget(self.btn_settings)

        lv.addLayout(footer)

        # Widgets "de linha" com altura fixa
        for w in (
            kdf_label, self.combo_profile,
            pad_label, self.combo_padding,
            self.date_expiration, self.check_expiration,
            self.password_input, self.btn_show_password,
            self.check_keyfile, self.keyfile_input, self.btn_pick_keyfile,
            self.check_hide_filename, self.check_delete, self.check_archive,
            self.check_vault, self.check_extract,
        ):
            w.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        
        # Campos e combos não devem crescer na vertical
        for w in (self.file_input, self.password_input, self.keyfile_input,
                  self.combo_profile, self.combo_padding, self.date_expiration):
            w.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        # Progress bar um pouco mais baixa (coerente com o CSS acima)
        self.progress_bar.setFixedHeight(14)

        # Botões com altura mínima menor
        for b in (self.btn_encrypt, self.btn_decrypt, self.btn_verify, self.btn_cancel,
                  self.btn_log, self.btn_change_pw, self.btn_vault, self.btn_settings):
            b.setMinimumHeight(28)

        # Anexa painel esquerdo e reserva espaço à direita p/ KeyGuard
        self.body_layout.addWidget(left, 1)                # fixa ao topo
        # (KeyGuard entra depois pelo _ensure_keyguard)

        # Status bar
        self.status_bar = QStatusBar(self)
        root.addWidget(self.status_bar)

# ------------------------------------------------------------------------------------------------------------------------------â•â•
#                              MAIN ENTRY POINT
# ------------------------------------------------------------------------------------------------------------------------------â•â•

if __name__ == "__main__":
    # P1.4: Early process hardening and initialization (bootstrap)
    try:
        from crypto_core.paths import ensure_base_dir
        from crypto_core.config import enable_process_hardening
        from crypto_core.memharden import harden_process_best_effort
        
        # Inicializar diretório base com permissões seguras
        ensure_base_dir()
        
        # Ativar proteções de processo
        enable_process_hardening()
        
        # Aplicar hardening de memória
        harden_process_best_effort()
        
    except Exception:
        # Best-effort - não deve quebrar a aplicação por falhas de hardening
        pass
    
    # Handler global de exceções para capturar todos os erros
    def global_exception_handler(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        # Registra com traceback completo
        logger.error("Exceção não tratada", exc_info=(exc_type, exc_value, exc_traceback))
    
    sys.excepthook = global_exception_handler
    
    app = QApplication(sys.argv)
    # i18n hook: load ./i18n/cryptguard_<locale>.qm if available
    try:
        from PySide6.QtCore import QLocale, QTranslator
        _tr = QTranslator()
        if _tr.load(QLocale.system(), "cryptguard", "_", "i18n"):
            app.installTranslator(_tr)
    except Exception:
        pass
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
