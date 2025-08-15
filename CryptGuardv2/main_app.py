#!/usr/bin/env python3
"""
CryptGuardv2 – secure GUI
Versão com interface clássica e core refatorado compatível com vault_v2.py e cg2_ops_v2.py
"""

from __future__ import annotations

# ─── Standard library ────────────────────────────────────────────────────────
import contextlib
import locale
import os
import shutil
import sys
import tempfile
import time
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional, Any
import warnings

# ─── PySide6 / Qt ────────────────────────────────────────────────────────────
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
)
from PySide6.QtGui import (
    QBrush,
    QColor,
    QDesktopServices,
    QDragEnterEvent,
    QDropEvent,
    QFont,
    QIcon,
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
    QStatusBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

# ─── Configuração de warnings e encoding ────────────────────────────────────
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

# ─── Imports do Projeto ──────────────────────────────────────────────────────
# Primeiro, verificamos qual versão usar (v2 refatorada ou original)
try:
    # Tenta importar versões refatoradas
    from crypto_core.cg2_ops import encrypt_to_cg2, decrypt_from_cg2
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
except ImportError:
    # Fallback para versões originais
    from crypto_core.cg2_ops import encrypt_to_cg2, decrypt_from_cg2
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

from crypto_core import LOG_PATH, SecurityProfile
from crypto_core.fileformat import is_cg2_file, read_header
from crypto_core.logger import logger
from crypto_core.utils import secure_delete, archive_folder
from crypto_core.verify_integrity import verify_integrity

# ─── Detecção de algoritmos disponíveis ─────────────────────────────────────
ALGOS = ["AES-256-GCM", "AES-256-CTR", "ChaCha20-Poly1305"]

# Detecta XChaCha20
try:
    from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
    XCHACHA20_AVAILABLE = True
    ALGOS.append("XChaCha20-Poly1305")
except ImportError:
    XCHACHA20_AVAILABLE = False
    # Tenta PyNaCl como fallback
    try:
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
        XCHACHA20_AVAILABLE = True
        ALGOS.append("XChaCha20-Poly1305")
    except ImportError:
        pass

# ════════════════════════════════════════════════════════════════════════════
#                              UI HELPERS (Estilo Antigo)
# ════════════════════════════════════════════════════════════════════════════

def human_speed(bytes_processed: int, elapsed_seconds: float) -> str:
    """Formata velocidade de transferência."""
    if elapsed_seconds <= 0:
        return "— MB/s"
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

# ════════════════════════════════════════════════════════════════════════════
#                           WORKER THREAD (Core mantido)
# ════════════════════════════════════════════════════════════════════════════

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
        algorithm: str = "AES-256-GCM",
        profile: SecurityProfile = SecurityProfile.BALANCED,
        delete_flag: bool = False,
        extra_params: Optional[dict] = None
    ):
        super().__init__()
        self.operation = operation
        self.src_path = src_path
        self.password = password
        self.algorithm = algorithm
        self.profile = profile
        self.delete_flag = delete_flag
        self.extra_params = extra_params or {}
        self._start_time = 0
        self._cancelled = False
    
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
                result = self._encrypt(progress_callback)
            else:
                result = self._decrypt(progress_callback)
            
            if not self._cancelled:
                self.finished.emit(str(result) if result else "")
                
        except InterruptedError:
            pass
        except Exception as e:
            logger.exception(f"CryptoWorker error during {self.operation}")
            self.error.emit(str(e))
    
    def _encrypt(self, progress_cb: Callable) -> Path:
        """Executa criptografia."""
        src = Path(self.src_path)
        out_path = self.extra_params.get("out_path", src.with_suffix(".cg2"))
        
        return Path(encrypt_to_cg2(
            src,
            out_path,
            self.password.encode(),
            self.algorithm,
            self.profile,
            exp_ts=self.extra_params.get("expires_at"),
            progress_cb=progress_cb,
            pad_block=self.extra_params.get("pad_block", 0)
        ))
    
    def _decrypt(self, progress_cb: Callable) -> Path:
        """Executa descriptografia."""
        src = Path(self.src_path)
        out_path = self.extra_params.get("out_path", src.with_suffix(""))
        
        result = decrypt_from_cg2(
            src,
            out_path,
            self.password.encode(),
            verify_only=False,
            progress_cb=progress_cb
        )
        
        return Path(result) if result else Path("")
    
    def cancel(self):
        """Cancela operação."""
        self._cancelled = True
        self.requestInterruption()

# ════════════════════════════════════════════════════════════════════════════
#                        MAIN WINDOW (Interface Antiga)
# ════════════════════════════════════════════════════════════════════════════

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptGuardv2 – secure")
        self.resize(940, 630)
        self.setMinimumSize(940, 630)
        
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
        
        # Constrói UI
        self._build_ui()
        
        # Enable drag & drop
        self.setAcceptDrops(True)
    
    def _apply_palette_old_theme(self):
        """Aplica paleta dark da UI antiga."""
        pal = QPalette()
        pal.setColor(QPalette.Window, QColor("#20232a"))
        pal.setColor(QPalette.Base, QColor("#2d3343"))
        pal.setColor(QPalette.Text, QColor("#eceff4"))
        pal.setColor(QPalette.Button, QColor("#37474F"))
        pal.setColor(QPalette.ButtonText, QColor("#ECEFF1"))
        pal.setColor(QPalette.Highlight, QColor("#29B6F6"))
        pal.setColor(QPalette.HighlightedText, QColor("#fefeff"))
        QApplication.setPalette(pal)
    
    def _build_ui(self):
        """Constrói UI no estilo antigo."""
        # Header
        header = QFrame()
        header.setFixedHeight(64)
        header.setStyleSheet(
            "QFrame{background:#263238;color:#ECEFF1;border-bottom:2px solid #37474F;}"
        )
        hlay = QHBoxLayout(header)
        hlay.setContentsMargins(18, 0, 18, 0)
        title = QLabel("🔐 CryptGuardv2", font=QFont("Inter", 20, QFont.DemiBold))
        title.setStyleSheet("color:white")
        hlay.addWidget(title)
        hlay.addStretch()
        # About / Help (paridade com UI nova)
        btn_about = QPushButton("About")
        btn_about.setStyleSheet(
            "QPushButton {background: transparent; color: #ECEFF1; "
            "border: 1px solid rgba(255,255,255,0.3); border-radius: 4px; padding: 5px 12px;}"
            "QPushButton:hover {background: rgba(255,255,255,0.1); "
            "border-color: rgba(255,255,255,0.5);}"
        )
        btn_about.clicked.connect(self._show_about)
        hlay.addWidget(btn_about)

        btn_help = QPushButton("Help")
        btn_help.setStyleSheet(
            "QPushButton {background: transparent; color: #ECEFF1; "
            "border: 1px solid rgba(255,255,255,0.3); border-radius: 4px; padding: 5px 12px;}"
            "QPushButton:hover {background: rgba(255,255,255,0.1); "
            "border-color: rgba(255,255,255,0.5);}"
        )
        btn_help.clicked.connect(self._show_help)
        hlay.addWidget(btn_help)
        
        # File selection (mantém nomes NOVOS!)
        self.file_input = QLineEdit()  # Nome NOVO
        self.file_input.setPlaceholderText("Drop a file or click Select…")
        self.file_input.setReadOnly(True)
        self.file_input.setAcceptDrops(False)
        
        btn_pick = AccentButton("Select…")
        btn_pick.clicked.connect(self._browse_file)  # Slot NOVO
        lay_file = QHBoxLayout()
        lay_file.addWidget(self.file_input)
        lay_file.addWidget(btn_pick)
        
        # Algoritmo (nome NOVO)
        self.combo_algorithm = self._combo(ALGOS)
        lay_alg = self._field("Algorithm", self.combo_algorithm)
        
        # Security Profile (nome NOVO)
        self.combo_profile = self._combo([p.name.title() for p in SecurityProfile])
        self.combo_profile.setCurrentIndex(1)  # Balanced
        lay_prof = self._field("Security profile", self.combo_profile)
        
        # Padding (nome NOVO)
        self.combo_padding = self._combo(["Off", "4 KiB", "16 KiB", "64 KiB", "1 MiB"])
        self.combo_padding.setToolTip(
            "Adds zero padding per chunk to hide exact size in transit.\n"
            "The real size is restored on decrypt."
        )
        lay_pad = self._field("Pad size", self.combo_padding)
        
        # Expiration (nomes NOVOS)
        self.date_expiration = ClickableDateEdit(QDate.currentDate())
        self.date_expiration.setCalendarPopup(True)
        self.date_expiration.setDisplayFormat("dd/MM/yyyy")
        self.date_expiration.setMinimumDate(QDate.currentDate())
        self.date_expiration.setEnabled(False)
        
        cal_btn = QPushButton("📅")
        cal_btn.setMaximumWidth(30)
        cal_btn.setStyleSheet("background:#37474F;color:#ECEFF1;border:1px solid #455A64;")
        cal_btn.setEnabled(False)
        cal_btn.clicked.connect(self._show_calendar_popup)
        
        self.check_expiration = QCheckBox("Enable expiration date")
        self.check_expiration.toggled.connect(self.date_expiration.setEnabled)
        self.check_expiration.toggled.connect(cal_btn.setEnabled)
        
        lab_exp = QLabel("Expiration date")
        lab_exp.setFont(QFont("Inter", 10, QFont.Bold))
        lay_exp = QHBoxLayout()
        lay_exp.addWidget(lab_exp)
        lay_exp.addWidget(self.date_expiration)
        lay_exp.addWidget(cal_btn)
        lay_exp.addWidget(self.check_expiration)
        lay_exp.addStretch()
        
        # Password (nomes NOVOS)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Password…")
        self.password_input.setMaximumWidth(280)
        self.password_input.textChanged.connect(self._update_password_strength)
        
        self.strength_bar = QProgressBar()
        self.strength_bar.setMaximum(4)
        self.strength_bar.setTextVisible(False)
        self.strength_bar.setFixedWidth(140)
        
        lay_pwd = QHBoxLayout()
        lay_pwd.addWidget(self.password_input)
        lay_pwd.addWidget(self.strength_bar)
        # 👁 Mostrar/ocultar senha (paridade com UI nova)
        self.btn_show_password = QPushButton("👁")
        self.btn_show_password.setCheckable(True)
        self.btn_show_password.setFixedSize(30, 30)
        self.btn_show_password.toggled.connect(self._toggle_password_visibility)
        lay_pwd.addWidget(self.btn_show_password)

        
        # Options (nomes NOVOS)
        self.check_delete = QCheckBox("Secure-delete input after operation")
        self.check_archive = QCheckBox("Archive folder before encrypt (ZIP)")
        self.check_vault = QCheckBox("Store encrypted file in Vault")
        self.check_extract = QCheckBox("Extract ZIP after decrypt")  # NOVO!
        self.check_extract.setVisible(False)  # esconde da UI
        
        # Buttons (nomes NOVOS)
        self.btn_encrypt = AccentButton("Encrypt")
        self.btn_decrypt = AccentButton("Decrypt")
        self.btn_verify = AccentButton("Verify")
        self.btn_cancel = AccentButton("Cancel")
        self.btn_cancel.setEnabled(False)
        
        self.btn_encrypt.clicked.connect(lambda: self._start_operation("encrypt"))
        self.btn_decrypt.clicked.connect(lambda: self._start_operation("decrypt"))
        self.btn_verify.clicked.connect(self._verify_file)
        self.btn_cancel.clicked.connect(self._cancel_operation)
        
        lay_btn = QHBoxLayout()
        lay_btn.addWidget(self.btn_encrypt)
        lay_btn.addWidget(self.btn_decrypt)
        lay_btn.addWidget(self.btn_verify)
        lay_btn.addWidget(self.btn_cancel)
        lay_btn.addStretch()
        
        # Progress (nomes NOVOS)
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setStyleSheet(
            "QProgressBar{background:#37474F;border:1px solid #263238;border-radius:5px;}"
            "QProgressBar::chunk{background:#29B6F6;}"
        )
        
        self.label_speed = QLabel("Speed: — MB/s")
        h_speed = QHBoxLayout()
        h_speed.addStretch()
        h_speed.addWidget(self.label_speed)
        
        # Layout central (ordem antiga)
        center = QVBoxLayout()
        center.setSpacing(16)
        center.setContentsMargins(22, 22, 22, 22)
        center.addLayout(lay_file)
        center.addLayout(lay_alg)
        center.addLayout(lay_prof)
        center.addLayout(lay_pad)
        center.addLayout(lay_exp)
        center.addLayout(lay_pwd)
        center.addWidget(self.check_delete, 0, Qt.AlignLeft)
        center.addWidget(self.check_archive, 0, Qt.AlignLeft)
        center.addWidget(self.check_vault, 0, Qt.AlignLeft)
        center.addWidget(self.check_extract, 0, Qt.AlignLeft)
        center.addLayout(lay_btn)
        center.addWidget(self.progress_bar)
        center.addLayout(h_speed)
        center.addStretch()
        
        central_frame = QFrame()
        central_frame.setLayout(center)
        central_frame.setStyleSheet("background:#263238;")
        
        # Status bar (nome NOVO)
        self.status_bar = QStatusBar()
        self.status_bar.showMessage("Ready.")
        self.status_bar.setStyleSheet("QStatusBar::item { border: 0px; }")
        
        log_btn = QPushButton("Log", clicked=self._open_log)
        log_btn.setStyleSheet("background:transparent;color:#90A4AE;")
        self.status_bar.addPermanentWidget(log_btn)
        
        change_pwd_btn = QPushButton("Change Password")
        change_pwd_btn.setStyleSheet("background:transparent;color:#90A4AE;")
        change_pwd_btn.clicked.connect(self._change_vault_password)
        self.status_bar.addPermanentWidget(change_pwd_btn)
        
        vault_btn = QPushButton("Vault")
        vault_btn.setStyleSheet("background:transparent;color:#90A4AE;")
        vault_btn.clicked.connect(self._open_vault)
        self.status_bar.addPermanentWidget(vault_btn)
        settings_btn = QPushButton("Settings")
        settings_btn.setStyleSheet("background:transparent;color:#90A4AE;")
        settings_btn.clicked.connect(self._show_settings)
        self.status_bar.addPermanentWidget(settings_btn)

        
        # Layout principal
        main = QVBoxLayout(self)
        main.setContentsMargins(0, 0, 0, 0)
        main.addWidget(header)
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.addWidget(central_frame, 1)
        main.addLayout(body)
        main.addWidget(self.status_bar)
        
        # Cria label_status para compatibilidade (não visível)
        self.label_status = QLabel()
        self.label_time = QLabel()
        
        # OPCIONAL: Cria aliases para compatibilidade total com código antigo
        self._create_aliases()
    
    def _create_aliases(self):
        """Cria aliases para compatibilidade com nomes antigos."""
        self.file_line = self.file_input
        self.cmb_alg = self.combo_algorithm
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
        
        self.strength_bar.setValue(score)
        colors = ["#d32f2f", "#f57c00", "#fbc02d", "#43a047", "#1b5e20"]
        self.strength_bar.setStyleSheet(f"QProgressBar::chunk{{background:{colors[min(score, 4)]};}}") 
    
    # ─────────────────────────────────────────────────────────────────────────
    #                           EVENT HANDLERS
    # ─────────────────────────────────────────────────────────────────────────
    
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
        """Auto-detecta algoritmo de arquivo CG2."""
        try:
            src = Path(path)
            if not src.exists() or src.is_dir():
                return
            if is_cg2_file(src):
                hdr, *_ = read_header(src)
                idx = self.combo_algorithm.findText(hdr.alg)
                if idx >= 0:
                    self.combo_algorithm.setCurrentIndex(idx)
                    self.status_bar.showMessage(f"Detected CG2 format: {hdr.alg}")
        except Exception as e:
            self.status_bar.showMessage(f"Could not detect algorithm: {e}")
    
    # ─────────────────────────────────────────────────────────────────────────
    #                               SLOTS
    # ─────────────────────────────────────────────────────────────────────────
    
    def _browse_file(self):
        """Abre diálogo para selecionar arquivo/pasta."""
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
    
    def _show_calendar_popup(self):
        """Mostra calendário do DateEdit."""
        if self.date_expiration.isEnabled():
            for child in self.date_expiration.children():
                if isinstance(child, QPushButton) or "QToolButton" in child.metaObject().className():
                    child.click()
                    return
            self.date_expiration.setFocus()
    
    def _toggle_password_visibility(self, checked: bool):
        """Alterna visibilidade da senha (paridade com main_app.py)."""
        if checked:
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.btn_show_password.setText("🔒")
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.btn_show_password.setText("👁")
    
    def _start_operation(self, operation: str):
        """Inicia operação de criptografia/descriptografia."""
        # Habilita/desabilita controles baseado na operação
        self.combo_algorithm.setEnabled(operation == "encrypt")
        self.combo_padding.setEnabled(operation == "encrypt")
        
        # Validações
        path = self.file_input.text()
        pwd = self.password_input.text()
        
        if not path:
            return self.status_bar.showMessage("Select a file first.")
        if not pwd:
            return self.status_bar.showMessage("Enter password.")
        
        self._is_encrypt = (operation == "encrypt")
        self._original_path = path
        src = path
        self._tmp_zip = None
        self._forced_out = ""
        
        src_path = Path(src)
        
        # Validação de pasta para decrypt
        if src_path.is_dir():
            if not self._is_encrypt:
                QMessageBox.warning(self, "Invalid Selection", "Please select a file for decrypt/verify.")
                return self.status_bar.showMessage("Select a file for decrypt/verify.")
            if not self.check_archive.isChecked():
                QMessageBox.information(
                    self,
                    "Auto-Archive",
                    "Folders require ZIP archiving for encryption. Enabling automatically."
                )
                self.check_archive.setChecked(True)
        
        # Empacota pasta → ZIP temporário antes de cifrar
        if self._is_encrypt and self.check_archive.isChecked() and src_path.is_dir():
            try:
                tmp_zip = archive_folder(src)
                self._tmp_zip = tmp_zip
                src = str(tmp_zip)
                # Força nome de saída consistente com o nome da pasta
                self._forced_out = str(Path(self.file_input.text()).with_suffix(".cg2"))
                
                # PATCH 7.1: Salva tamanho real do ZIP para progresso correto
                self._operation_size = Path(tmp_zip).stat().st_size
            except Exception as e:
                return self.status_bar.showMessage(f"Zip error: {e}")
        
        # Total para barra de progresso
        try:
            src_size = Path(src).stat().st_size
        except FileNotFoundError:
            if self._tmp_zip:
                with contextlib.suppress(Exception):
                    os.remove(self._tmp_zip)
            return self.status_bar.showMessage(f"Source file not found: {src}")
        except Exception as e:
            if self._tmp_zip:
                with contextlib.suppress(Exception):
                    os.remove(self._tmp_zip)
            return self.status_bar.showMessage(f"Error accessing file: {e}")
        
        # Algoritmo
        algo_idx = self.combo_algorithm.currentIndex()
        profile = list(SecurityProfile)[self.combo_profile.currentIndex()]
        algo_names = {0: "AES-256-GCM", 1: "AES-256-CTR", 2: "ChaCha20-Poly1305"}
        if XCHACHA20_AVAILABLE:
            algo_names[3] = "XChaCha20-Poly1305"
        alg_name = algo_names.get(algo_idx, "AES-256-GCM")
        
        if self._is_encrypt:
            self.status_bar.showMessage(f"Encrypting with {alg_name} (CG2 format)")
        else:
            if is_cg2_file(src):
                self.status_bar.showMessage("Decrypting CG2 format")
            else:
                self.status_bar.showMessage("Decrypting legacy format")
        
        delete_flag = self.check_delete.isChecked()
        
        # Parâmetros extras
        extra: dict[str, Any] = {}
        
        if self._is_encrypt and self.check_expiration.isChecked():
            qd = self.date_expiration.date()
            exp_dt = datetime(qd.year(), qd.month(), qd.day(), tzinfo=UTC)
            if exp_dt.date() < datetime.now(UTC).date():
                return self.status_bar.showMessage("Expiration date cannot be in the past.")
            extra["expires_at"] = int(exp_dt.timestamp())
        
        if self._is_encrypt:
            pad_map = {"Off": 0, "4 KiB": 4096, "16 KiB": 16384, "64 KiB": 65536, "1 MiB": 1048576}
            extra["pad_block"] = pad_map.get(self.combo_padding.currentText(), 0)
            
            # Output path
            if self._forced_out:
                extra["out_path"] = self._forced_out
            else:
                extra["out_path"] = str(Path(src).with_suffix(".cg2"))
        
        # Se não setamos _operation_size ainda, seta agora
        if not hasattr(self, "_operation_size"):
            self._operation_size = src_size
        
        self._toggle(False)
        self.progress_bar.setMaximum(0)
        self.progress_bar.setValue(0)
        self.status_bar.showMessage("Deriving key (Argon2)…")
        
        # Cria e inicia worker
        self.worker = CryptoWorker(
            operation,
            src,
            pwd,
            alg_name,
            profile,
            delete_flag,
            extra
        )
        
        self.worker.progress.connect(self._update_progress)
        self.worker.finished.connect(self._operation_finished)
        self.worker.error.connect(self._operation_error)
        self.worker.start()
        
        # Limpa senha
        self.password_input.clear()
    
    def _verify_file(self):
        """Verifica integridade de arquivo criptografado."""
        path = self.file_input.text()
        pwd = self.password_input.text()
        
        if not path or not pwd:
            return self.status_bar.showMessage("Select file and enter password.")
        
        profile = list(SecurityProfile)[self.combo_profile.currentIndex()]
        
        try:
            if verify_integrity(path, pwd, profile):
                QMessageBox.information(self, "Verify", "Integridade OK.")
            else:
                raise ValueError("Integridade falhou.")
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Verificação falhou: {str(e)}")
        
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
            
            self.status_bar.showMessage("ℹ️ Operação cancelada.", 5000)
            self.btn_cancel.setEnabled(False)
            self._toggle(True)
            
            if self._tmp_zip:
                with contextlib.suppress(Exception):
                    os.remove(self._tmp_zip)
            
            try:
                self.worker.password = None
            finally:
                self.worker.finished.emit("")
    
    def _toggle(self, enabled: bool):
        """Habilita/desabilita controles."""
        for w in (
            self.btn_encrypt,
            self.btn_decrypt,
            self.btn_verify,
            self.combo_algorithm,
            self.combo_profile,
            self.combo_padding,
            self.password_input,
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
            self.label_speed.setText("Speed: — MB/s")
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
        """Operação concluída com sucesso."""
        if not out_path:
            self.status_bar.showMessage("Operation cancelled.", 5000)
            self._toggle(True)
            return
        
        self.progress_bar.setValue(100)
        
        # Limpa ZIP temporário
        if hasattr(self, "_tmp_zip") and self._tmp_zip:
            Path(self._tmp_zip).unlink(missing_ok=True)
        
        final_output = out_path
        
        # PATCH 7.2: Extração automática pós-decrypt
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
        
        self.status_bar.showMessage("✔️ Done.", 8000)
        
        # Limpa _operation_size
        if hasattr(self, "_operation_size"):
            delattr(self, "_operation_size")
        
        try:
            if hasattr(self, "worker"):
                self.worker.password = None
        finally:
            self._toggle(True)
    
    def _operation_error(self, msg: str):
        """Erro na operação."""
        if getattr(self, "_tmp_zip", None):
            with contextlib.suppress(Exception):
                os.remove(self._tmp_zip)
        
        # Traduz erros comuns
        if "InvalidTag" in msg or "MAC check failed" in msg:
            msg = "Senha ou arquivo incorretos."
        elif "expired" in msg.lower():
            msg = "Arquivo expirado, não pode ser descriptografado."
        
        QMessageBox.critical(self, "Erro", msg)
        self.status_bar.showMessage(f"Error: {msg}", 10000)
        
        # Limpa _operation_size
        if hasattr(self, "_operation_size"):
            delattr(self, "_operation_size")
        
        try:
            if hasattr(self, "worker"):
                self.worker.password = None
        finally:
            self._toggle(True)
    
    # ─────────────────────────────────────────────────────────────────────────
    #                          VAULT & DIALOGS
    # ─────────────────────────────────────────────────────────────────────────
    
    def _open_vault(self):
        """Abre diálogo do Vault."""
        while True:
            if self.vm is None:
                pw, ok = QInputDialog.getText(
                    self,
                    "Vault",
                    "Master-password:",
                    QLineEdit.Password
                )
                if not ok or not pw:
                    return
                
                try:
                    # Obtém caminho do vault
                    vault_path = Config.default_vault_path()
                    
                    if vault_path.exists() and vault_path.stat().st_size == 0:
                        vault_path.unlink()
                    
                    exists = vault_path.exists()
                    
                    if not exists:
                        # Cria novo vault
                        if USING_V2:
                            vm = VaultManager(AtomicStorageBackend(vault_path))
                        else:
                            # Implementação básica local para compatibilidade
                            class SimpleBackend:
                                def __init__(self, path):
                                    self.path = Path(path)
                                    self.path.parent.mkdir(parents=True, exist_ok=True)
                                
                                def save(self, data: bytes):
                                    self.path.write_bytes(data)
                                
                                def load(self) -> bytes:
                                    return self.path.read_bytes() if self.path.exists() else b""
                            
                            vm = VaultManager(storage=SimpleBackend(vault_path))
                        
                        vm.create(SecureMemory(pw))
                        self.vm = vm
                        self.status_bar.showMessage("Novo Vault criado com sucesso.", 8000)
                    else:
                        self.vm = open_or_init_vault(pw, vault_path)
                        self.status_bar.showMessage("Vault aberto com sucesso.", 8000)
                
                except CorruptVault:
                    if QMessageBox.question(
                        self,
                        "Vault corrompido",
                        "O arquivo vault3.dat parece corrompido.\nDeseja sobrescrevê-lo?",
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No,
                    ) == QMessageBox.Yes:
                        vault_path.unlink(missing_ok=True)
                        continue
                    else:
                        return
                
                except WrongPassword:
                    QMessageBox.warning(self, "Vault", "Senha do Vault incorreta. Tente novamente.")
                    continue
                
                except VaultLocked as e:
                    QMessageBox.warning(self, "Vault Bloqueado", str(e))
                    return
                
                finally:
                    pw = ""
            
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
            break
    
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
            self.vm.change_password(SecureMemory(old_pw), SecureMemory(new_pw))
            QMessageBox.information(self, "Sucesso", "Senha do Vault alterada com sucesso.")
        except WrongPassword:
            QMessageBox.critical(self, "Senha incorreta", "A senha atual está incorreta.")
        except Exception as e:
            QMessageBox.critical(self, "Erro", str(e))
        finally:
            old_pw = new_pw = confirm = ""
    
    def _show_settings(self):
        """Mostra diálogo de configurações (paridade com main_app.py)."""
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
                f"Não foi possível abrir o log:\n{e}\n\nCaminho: {LOG_PATH}"
            )
    def _show_about(self):
        """Mostra diálogo Sobre (paridade com main_app.py)."""
        QMessageBox.about(
            self,
            "About CryptGuardv2",
            "<h3>CryptGuardv2</h3>"
            "<p>Version 2.7.0</p>"
            "<p>Secure file encryption with modern algorithms.</p>"
            "<br>"
            "<p><b>Features:</b></p>"
            "<ul>"
            "<li>AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305</li>"
            "<li>Argon2id key derivation</li>"
            "<li>Authenticated encryption (AEAD)</li>"
            "<li>Anti-truncation protection</li>"
            "<li>Optional padding for size obfuscation</li>"
            "<li>Secure Vault for encrypted files</li>"
            "</ul>"
            "<br>"
            "<p>© 2024-2025 CryptGuard Team</p>"
        )

    def _show_help(self):
        """Mostra diálogo de ajuda (paridade com main_app.py)."""
        QMessageBox.information(
            self,
            "Help",
            "<h3>How to use CryptGuardv2</h3>"
            "<br>"
            "<p><b>To Encrypt:</b></p>"
            "<ol>"
            "<li>Select a file or folder</li>"
            "<li>Choose algorithm and security level</li>"
            "<li>Enter a strong password</li>"
            "<li>Click Encrypt</li>"
            "</ol>"
            "<br>"
            "<p><b>To Decrypt:</b></p>"
            "<ol>"
            "<li>Select an encrypted .cg2 file</li>"
            "<li>Enter the password</li>"
            "<li>Click Decrypt</li>"
            "</ol>"
            "<br>"
            "<p><b>Tips:</b></p>"
            "<ul>"
            "<li>Use strong passwords (12+ characters)</li>"
            "<li>Store encrypted files in the Vault for extra security</li>"
            "<li>Enable padding to hide file sizes</li>"
            "<li>Set expiration dates for sensitive files</li>"
            "</ul>"
        )

# ════════════════════════════════════════════════════════════════════════════
#                              MAIN ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())