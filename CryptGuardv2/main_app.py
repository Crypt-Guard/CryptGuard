#!/usr/bin/env python3
"""
CryptGuardv2 – secure GUI
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

# ─── Projeto (backend) ───────────────────────────────────────────────────────
from crypto_core import LOG_PATH, SecurityProfile
from crypto_core import decrypt as cg_decrypt  # manter decrypt legado
from crypto_core.factories import encrypt as enc2
from crypto_core.fileformat import is_cg2_file
from crypto_core.logger import logger
from crypto_core.utils import secure_delete

from vault import (
    Config,
    CorruptVault,
    SecureMemory,
    VaultDialog,
    VaultManager,
    WrongPassword,
    open_or_init_vault,
)

warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*utcfromtimestamp.*")

# stdout/stderr UTF-8 no Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

locale.setlocale(locale.LC_ALL, "")  # para formatação

# Detecta XChaCha20 (PyNaCl bindings)
try:
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt  # noqa: F401
    XCHACHA20_AVAILABLE = True
except Exception:
    XCHACHA20_AVAILABLE = False

ALGOS = ["AES-256-GCM", "AES-256-CTR", "ChaCha20-Poly1305"]
if XCHACHA20_AVAILABLE:
    ALGOS.append("XChaCha20-Poly1305")


# ════════════════════════════════════════════════════════════════════════════
#                              UI helpers
# ════════════════════════════════════════════════════════════════════════════
def human_speed(bytes_processed: int, elapsed_seconds: float) -> str:
    if elapsed_seconds <= 0:
        return "– MB/s"
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
    """Botão azul com animação de hover."""

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
        self.setStyleSheet(
            f"""
            QPushButton {{
                background:{color}; color:white; border:none;
                border-radius:{self._radius}px; padding:9px 24px;
                font-weight:600; letter-spacing:0.3px;
            }}
            QPushButton:disabled {{background:#4e586e;}}
        """
        )

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
    def paintEvent(self, evt):
        painter = QPainter(self)
        g = QLinearGradient(QPoint(0, 0), QPoint(self.width(), 0))
        g.setColorAt(0, QColor("#667eea"))
        g.setColorAt(1, QColor("#764ba2"))
        painter.fillRect(self.rect(), QBrush(g))


# ══════════════════════ Worker Thread ═══════════════════════════════════
class CryptoWorker(QThread):
    progress = Signal(int, float)
    finished = Signal(str)
    error = Signal(str)

    def __init__(
        self,
        func: Callable,
        src: str,
        pwd: str,
        profile: SecurityProfile,
        delete_flag: bool,
        extra: dict | None = None,
    ):
        super().__init__()
        self.func = func
        self.src = src
        self.pwd = pwd
        self.profile = profile
        self.delete_flag = delete_flag
        self.extra = extra or {}
        self._start_time = time.time()

    def run(self):
        try:

            def progress_callback(bytes_done: int):
                if self.isInterruptionRequested():
                    raise InterruptedError("Operation cancelled by user")
                elapsed = time.time() - self._start_time
                self.progress.emit(bytes_done, elapsed)

            result = self.func(
                self.src,
                self.pwd,
                self.profile,
                progress_cb=progress_callback,
                **self.extra,
            )
            if not self.isInterruptionRequested():
                self.finished.emit("" if result is None else str(result))
        except InterruptedError:
            pass
        except Exception as e:
            logger.exception("CryptoWorker error")
            self.error.emit(str(e))


# ══════════════════════ Main Window ══════════════════════════════════════
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptGuardv2 – secure")
        self.resize(940, 630)
        self.setMinimumSize(940, 630)
        self._apply_palette()
        self.vm: VaultManager | None = None
        self._build_ui()

    def _build_ui(self):
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

        self.file_line = QLineEdit()
        self.file_line.setPlaceholderText("Drop a file or click Select…")
        self.file_line.setReadOnly(True)
        self.file_line.setAcceptDrops(False)
        self.setAcceptDrops(True)
        btn_pick = AccentButton("Select…")
        btn_pick.clicked.connect(self._pick)
        lay_file = QHBoxLayout()
        lay_file.addWidget(self.file_line)
        lay_file.addWidget(btn_pick)

        self.cmb_alg = self._combo(ALGOS)
        self.cmb_prof = self._combo([p.name.title() for p in SecurityProfile])
        lay_alg = self._field("Algorithm", self.cmb_alg)
        lay_prof = self._field("Security profile", self.cmb_prof)

        self.cmb_pad = self._combo(["Off", "4 KiB", "16 KiB", "64 KiB", "1 MiB"])
        self.cmb_pad.setToolTip(
            "Adds zero padding per chunk to hide exact size in transit.\n"
            "The real size is restored on decrypt."
        )
        lay_pad = self._field("Pad size", self.cmb_pad)

        self.date_exp = ClickableDateEdit(QDate.currentDate())
        self.date_exp.setCalendarPopup(True)
        self.date_exp.setDisplayFormat("dd/MM/yyyy")
        self.date_exp.setMinimumDate(QDate.currentDate())
        self.date_exp.setEnabled(False)

        cal_btn = QPushButton("📅")
        cal_btn.setMaximumWidth(30)
        cal_btn.setStyleSheet("background:#37474F;color:#ECEFF1;border:1px solid #455A64;")
        cal_btn.setEnabled(False)
        cal_btn.clicked.connect(self._show_calendar_popup)

        self.chk_exp = QCheckBox("Enable expiration date")
        self.chk_exp.toggled.connect(self.date_exp.setEnabled)
        self.chk_exp.toggled.connect(cal_btn.setEnabled)

        lab_exp = QLabel("Expiration date")
        lab_exp.setFont(QFont("Inter", 10, QFont.Bold))
        lay_exp = QHBoxLayout()
        lay_exp.addWidget(lab_exp)
        lay_exp.addWidget(self.date_exp)
        lay_exp.addWidget(cal_btn)
        lay_exp.addWidget(self.chk_exp)
        lay_exp.addStretch()

        self.pwd = QLineEdit()
        self.pwd.setEchoMode(QLineEdit.Password)
        self.pwd.setPlaceholderText("Password…")
        self.pwd.setMaximumWidth(280)
        self.pwd.textChanged.connect(self._update_strength)
        self.str_bar = QProgressBar()
        self.str_bar.setMaximum(4)
        self.str_bar.setTextVisible(False)
        self.str_bar.setFixedWidth(140)
        lay_pwd = QHBoxLayout()
        lay_pwd.addWidget(self.pwd)
        lay_pwd.addWidget(self.str_bar)

        self.chk_del = QCheckBox("Secure-delete input after operation")
        self.chk_archive = QCheckBox("Archive folder before encrypt (ZIP)")
        self.chk_vault = QCheckBox("Store encrypted file in Vault")

        self.btn_enc = AccentButton("Encrypt")
        self.btn_dec = AccentButton("Decrypt")
        self.btn_verify = AccentButton("Verify")
        self.btn_cancel = AccentButton("Cancel")
        self.btn_cancel.setEnabled(False)
        self.btn_enc.clicked.connect(lambda: self._start(True))
        self.btn_dec.clicked.connect(lambda: self._start(False))
        self.btn_verify.clicked.connect(self._verify)
        self.btn_cancel.clicked.connect(self._cancel_current_task)
        lay_btn = QHBoxLayout()
        lay_btn.addWidget(self.btn_enc)
        lay_btn.addWidget(self.btn_dec)
        lay_btn.addWidget(self.btn_verify)
        lay_btn.addWidget(self.btn_cancel)
        lay_btn.addStretch()

        self.prg = QProgressBar()
        self.prg.setValue(0)
        self.prg.setAlignment(Qt.AlignCenter)
        self.prg.setStyleSheet(
            "QProgressBar{background:#37474F;border:1px solid #263238;border-radius:5px;}"
            "QProgressBar::chunk{background:#29B6F6;}"
        )
        self.lbl_speed = QLabel("Speed: – MB/s")
        h_speed = QHBoxLayout()
        h_speed.addStretch()
        h_speed.addWidget(self.lbl_speed)

        center = QVBoxLayout()
        center.setSpacing(16)
        center.setContentsMargins(22, 22, 22, 22)
        center.addLayout(lay_file)
        center.addLayout(lay_alg)
        center.addLayout(lay_prof)
        center.addLayout(lay_pad)
        center.addLayout(lay_exp)
        center.addLayout(lay_pwd)
        center.addWidget(self.chk_del, 0, Qt.AlignLeft)
        center.addWidget(self.chk_archive, 0, Qt.AlignLeft)
        center.addWidget(self.chk_vault, 0, Qt.AlignLeft)
        center.addLayout(lay_btn)
        center.addWidget(self.prg)
        center.addLayout(h_speed)
        center.addStretch()
        central_frame = QFrame()
        central_frame.setLayout(center)
        central_frame.setStyleSheet("background:#263238;")

        self.status = QStatusBar()
        self.status.showMessage("Ready.")
        self.status.setStyleSheet("QStatusBar::item { border: 0px; }")
        log_btn = QPushButton("Log", clicked=self._open_log)
        log_btn.setStyleSheet("background:transparent;color:#90A4AE;")
        self.status.addPermanentWidget(log_btn)
        change_pwd_btn = QPushButton("Change Password")
        change_pwd_btn.setStyleSheet("background:transparent;color:#90A4AE;")
        change_pwd_btn.clicked.connect(self._dlg_change_password)
        self.status.addPermanentWidget(change_pwd_btn)
        vault_btn = QPushButton("Vault")
        vault_btn.setStyleSheet("background:transparent;color:#90A4AE;")
        vault_btn.clicked.connect(self._open_vault)
        self.status.addPermanentWidget(vault_btn)

        main = QVBoxLayout(self)
        main.setContentsMargins(0, 0, 0, 0)
        main.addWidget(header)
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.addWidget(central_frame, 1)
        main.addLayout(body)
        main.addWidget(self.status)

    # ───────────────────────── Palette & helpers ─────────────────────────
    def _apply_palette(self):
        pal = QPalette()
        pal.setColor(QPalette.Window, QColor("#20232a"))
        pal.setColor(QPalette.Base, QColor("#2d3343"))
        pal.setColor(QPalette.Text, QColor("#eceff4"))
        pal.setColor(QPalette.Button, QColor("#37474F"))
        pal.setColor(QPalette.ButtonText, QColor("#ECEFF1"))
        pal.setColor(QPalette.Highlight, QColor("#29B6F6"))
        pal.setColor(QPalette.HighlightedText, QColor("#fefeff"))
        QApplication.setPalette(pal)

    def _field(self, label: str, widget):
        lab = QLabel(label)
        lab.setFont(QFont("Inter", 10, QFont.Bold))
        lay = QHBoxLayout()
        lay.addWidget(lab)
        lay.addWidget(widget)
        lay.addStretch()
        return lay

    def _combo(self, items):
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

    def _update_strength(self, txt: str):
        try:
            from zxcvbn import zxcvbn  # opcional
        except Exception:
            return
        score = zxcvbn(txt)["score"] if txt else 0
        self.str_bar.setValue(score)
        colors = ["#d32f2f", "#f57c00", "#fbc02d", "#43a047", "#1b5e20"]
        self.str_bar.setStyleSheet(f"QProgressBar::chunk{{background:{colors[score]};}}")

    # ───────────────────────── Drag & drop events ────────────────────────
    def dragEnterEvent(self, e: QDragEnterEvent):  # noqa: N802
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e: QDropEvent):  # noqa: N802
        urls = e.mimeData().urls()
        if not urls:
            return
        path = Path(urls[0].toLocalFile())
        if path.exists():
            self.file_line.setText(str(path))
            self._detect_algo(str(path))
            if path.is_dir():
                self.status.showMessage(f"Folder loaded via drag & drop: {path.name}")
                if not self.chk_archive.isChecked():
                    self.chk_archive.setChecked(True)
            else:
                file_type = "CG2" if is_cg2_file(path) else "file"
                self.status.showMessage(f"{file_type} loaded via drag & drop: {path.name}")

    # ───────────────────────── File picker dialog ───────────────────────
    def _pick(self):
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
                self.file_line.setText(f)
                self._detect_algo(f)
                self.status.showMessage("File selected.")
        else:
            folder = QFileDialog.getExistingDirectory(self, "Choose folder")
            if folder:
                self.file_line.setText(folder)
                self._detect_algo(folder)
                self.status.showMessage("Folder selected.")

    # ───────────────────────── Detect algorithm from file ────────────────
    def _detect_algo(self, path: str):
        try:
            src = Path(path)
            if not src.exists() or src.is_dir():
                return
            if is_cg2_file(src):
                from crypto_core.fileformat import read_header
                hdr, *_ = read_header(src)
                idx = self.cmb_alg.findText(hdr.alg)
                if idx >= 0:
                    self.cmb_alg.setCurrentIndex(idx)
                    self.status.showMessage(f"Detected CG2 format: {hdr.alg}")
                return
        except Exception as e:
            self.status.showMessage(f"Could not detect algorithm: {e}")

    # ───────────────────────── Progress callbacks ───────────────────────
    def _progress(self, done: int, elapsed: float):
        if self.prg.maximum() == 0:
            self.prg.setMaximum(100)
        total = getattr(self, "_total_bytes", 0)
        if total:
            pct = min(int(done * 100 / total), 100)
            self.prg.setValue(pct)
        speed = human_speed(done, elapsed)
        self.lbl_speed.setText(f"Speed: {speed}")

    def _done(self, out_path: str):
        if not out_path:
            self.status.showMessage("Operation cancelled.", 5000)
            self._toggle(True)
            return

        self.prg.setValue(100)

        if hasattr(self, "_tmp_zip") and self._tmp_zip:
            Path(self._tmp_zip).unlink(missing_ok=True)

        final_output = out_path

        # Se decrypt gerou ZIP, extrai para pasta com mesmo nome
        if not self._is_encrypt and out_path.endswith(".zip") and zipfile.is_zipfile(out_path):
            dest_dir = Path(out_path).with_suffix("")
            with tempfile.TemporaryDirectory() as tmp_extract:
                tmp_path = Path(tmp_extract)
                try:
                    with zipfile.ZipFile(out_path, "r") as zf:
                        for member in zf.infolist():
                            name = member.filename.lower()
                            if name.endswith("desktop.ini") or name.startswith(".") or name.endswith("thumbs.db"):
                                continue
                            target = tmp_path / member.filename
                            target.parent.mkdir(parents=True, exist_ok=True)
                            if not member.is_dir():
                                with zf.open(member) as src, open(target, "wb") as dst:
                                    shutil.copyfileobj(src, dst)
                    if dest_dir.exists():
                        if dest_dir.is_file():
                            dest_dir.unlink()
                        else:
                            shutil.rmtree(dest_dir)
                    shutil.move(str(tmp_path), str(dest_dir))
                    final_output = str(dest_dir)
                except Exception as e:
                    QMessageBox.critical(self, "Extraction Error", f"Failed to extract ZIP: {e}")
                    self.status.showMessage(f"❌ Extraction failed: {e}", 10000)
                    self.btn_cancel.setEnabled(False)
                    self._toggle(True)
                    return
            Path(out_path).unlink(missing_ok=True)

        # Vault (opcional)
        if self._is_encrypt and self.chk_vault.isChecked():
            try:
                if self.vm is None:
                    self._open_vault()
                    if self.vm is None:
                        raise RuntimeError("Vault not opened")
                self.vm.add_file(final_output)
                Path(final_output).unlink(missing_ok=True)
                self.status.showMessage("File moved to Vault.", 8000)
                QMessageBox.information(self, "Success", "File encrypted and moved to Vault successfully.")
            except Exception as e:
                QMessageBox.warning(self, "Vault", f"Could not store file in Vault:\n{e}")
                QMessageBox.information(self, "Success", f"Output file:\n{Path(final_output).name}")
        else:
            QMessageBox.information(self, "Success", f"Output file:\n{Path(final_output).name}")

        # Secure-delete
        if self.chk_del.isChecked():
            try:
                p = Path(self._original_path)
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    secure_delete(self._original_path, passes=1)
            except Exception as e:
                self.status.showMessage(f"Delete failed: {e}", 8000)

        self.status.showMessage("✔️ Done.", 8000)
        try:
            if hasattr(self, "worker"):
                self.worker.pwd = None
        finally:
            self._toggle(True)

    def _err(self, msg: str):
        if getattr(self, "_tmp_zip", None):
            with contextlib.suppress(Exception):
                os.remove(self._tmp_zip)
        QMessageBox.critical(self, "Erro", self._translate_error(msg))
        self.status.showMessage(f"Error: {self._translate_error(msg)}", 10000)
        try:
            if hasattr(self, "worker"):
                self.worker.pwd = None
        finally:
            self._toggle(True)

    def _cancel_current_task(self):
        if hasattr(self, "worker") and self.worker and self.worker.isRunning():
            self.worker.requestInterruption()
            if not self.worker.wait(5000):
                timer = QTimer(self)
                timer.timeout.connect(self.worker.quit)
                timer.start(100)
                self.worker.wait(1000)
            self.status.showMessage("⏹️ Operação cancelada.", 5000)
            self.btn_cancel.setEnabled(False)
            self._toggle(True)
            if getattr(self, "_tmp_zip", None):
                with contextlib.suppress(Exception):
                    os.remove(self._tmp_zip)
            try:
                self.worker.pwd = None
            finally:
                self.worker.finished.emit("")

    def _verify(self):
        from crypto_core.verify_integrity import verify_integrity
        path, pwd = self.file_line.text(), self.pwd.text()
        if not path or not pwd:
            return self.status.showMessage("Select file and enter password.")
        profile = list(SecurityProfile)[self.cmb_prof.currentIndex()]
        try:
            if verify_integrity(path, pwd, profile):
                QMessageBox.information(self, "Verify", "Integridade OK.")
            else:
                raise ValueError("Integridade falhou.")
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Verificação falhou: {str(e)}")
        self.pwd.clear()

    def _translate_error(self, msg: str) -> str:
        if "InvalidTag" in msg or "MAC check failed" in msg:
            return "Senha ou arquivo incorretos."
        return msg

    def _start(self, do_encrypt: bool):
        self.cmb_alg.setEnabled(do_encrypt)
        self.cmb_pad.setEnabled(do_encrypt)

        path, pwd = self.file_line.text(), self.pwd.text()
        if not path:
            return self.status.showMessage("Select a file first.")
        if not pwd:
            return self.status.showMessage("Enter password.")

        self._is_encrypt = do_encrypt
        original_path = path
        src = path
        tmp_zip = None
        self._forced_out = ""

        src_path = Path(src)
        if src_path.is_dir():
            if not do_encrypt:
                QMessageBox.warning(self, "Invalid Selection", "Please select a file for decrypt/verify.")
                return self.status.showMessage("Select a file for decrypt/verify.")
            if not self.chk_archive.isChecked():
                QMessageBox.information(self, "Auto-Archive", "Folders require ZIP archiving for encryption. Enabling automatically.")
                self.chk_archive.setChecked(True)

        # Empacota pasta → ZIP temporário antes de cifrar
        if do_encrypt and self.chk_archive.isChecked() and src_path.is_dir():
            try:
                from crypto_core.utils import archive_folder
                tmp_zip = archive_folder(src)
                src = str(tmp_zip)
                # Força nome de saída consistente com o nome da pasta selecionada:
                self._forced_out = str(Path(self.file_line.text()).with_suffix(".cg2"))
            except Exception as e:
                return self.status.showMessage(f"Zip error: {e}")

        # Total para barra de progresso
        try:
            src_size = Path(src).stat().st_size
        except FileNotFoundError:
            if tmp_zip:
                with contextlib.suppress(Exception):
                    os.remove(tmp_zip)
            return self.status.showMessage(f"Source file not found: {src}")
        except Exception as e:
            if tmp_zip:
                with contextlib.suppress(Exception):
                    os.remove(tmp_zip)
            return self.status.showMessage(f"Error accessing file: {e}")

        algo_idx = self.cmb_alg.currentIndex()
        profile = list(SecurityProfile)[self.cmb_prof.currentIndex()]
        algo_names = {0: "AES-256-GCM", 1: "AES-256-CTR", 2: "ChaCha20-Poly1305"}
        if XCHACHA20_AVAILABLE:
            algo_names[3] = "XChaCha20-Poly1305"
        alg_name = algo_names.get(algo_idx, "AES-256-GCM")

        if do_encrypt:
            self.status.showMessage(f"Encrypting with {alg_name} (CG2 format)")
        else:
            if is_cg2_file(src):
                self.status.showMessage("Decrypting CG2 format")
            else:
                self.status.showMessage("Decrypting legacy format")

        delete_flag = self.chk_del.isChecked()
        self._tmp_zip = tmp_zip
        self._original_path = original_path

        extra: dict[str, int] = {}
        if do_encrypt and self.chk_exp.isChecked():
            qd = self.date_exp.date()
            exp_dt = datetime(qd.year(), qd.month(), qd.day(), tzinfo=UTC)
            if exp_dt.date() < datetime.now(UTC).date():
                return self.status.showMessage("Expiration date cannot be in the past.")
            extra["expires_at"] = int(exp_dt.timestamp())

        if do_encrypt:
            pad_map = {"Off": 0, "4 KiB": 4096, "16 KiB": 16 * 1024, "64 KiB": 64 * 1024, "1 MiB": 1 << 20}
            extra["pad_block"] = pad_map.get(self.cmb_pad.currentText(), 0)

        self._total_bytes = src_size
        self._toggle(False)
        self.prg.setMaximum(0)
        self.prg.setValue(0)
        self.status.showMessage("Deriving key (Argon2)…")
        # Funções de execução em thread
        # Funções de execução em thread (canônicas)
        if do_encrypt:
            def func(path, pwd, prof, *, progress_cb=None, **kw):
                # Calcula out_path (forçado quando origem era pasta ZIPada)
                forced = getattr(self, "_forced_out", "")
                outp = forced if forced else str(Path(path).with_suffix(".cg2"))
                algo_names = {0: "AES-256-GCM", 1: "AES-256-CTR", 2: "ChaCha20-Poly1305"}
                if getattr(type(self), "XCHACHA20_AVAILABLE", False) or globals().get("XCHACHA20_AVAILABLE"):
                    algo_names[3] = "XChaCha20-Poly1305"
                alg_name = algo_names.get(self.cmb_alg.currentIndex(), "AES-256-GCM")
                return enc2(
                    path,
                    pwd,
                    algo=alg_name,
                    out_path=outp,
                    profile=prof,
                    progress_cb=progress_cb,
                    **kw,
                )
        else:
            def func(path, pwd, prof_hint, *, progress_cb=None, **kw):
                from crypto_core import decrypt as cg_decrypt
                return cg_decrypt(path, pwd, progress_cb=progress_cb, **kw)
        
        

        self.worker = CryptoWorker(func, src, pwd, profile, delete_flag, extra=extra)
        self.worker.progress.connect(self._progress)
        self.worker.finished.connect(self._done)
        self.worker.error.connect(self._err)
        self._t_start = time.time()
        self.worker.start()
        self.pwd.clear()

    def _toggle(self, enabled: bool):
        for w in (
            self.btn_enc,
            self.btn_dec,
            self.btn_verify,
            self.cmb_alg,
            self.cmb_prof,
            self.cmb_pad,
            self.pwd,
            self.chk_del,
            self.chk_archive,
            self.chk_vault,
            self.chk_exp,
            self.date_exp,
        ):
            w.setEnabled(enabled)
        if enabled:
            self.btn_cancel.setEnabled(False)
            self.prg.setMaximum(100)
            self.lbl_speed.setText("Speed: – MB/s")
            if hasattr(self, "worker"):
                del self.worker
        else:
            self.btn_cancel.setEnabled(True)

    def _show_calendar_popup(self):
        if self.date_exp.isEnabled():
            for child in self.date_exp.children():
                if isinstance(child, QPushButton) or "QToolButton" in child.metaObject().className():
                    child.click()
                    return
            self.date_exp.setFocus()

    def _dlg_change_password(self):
        if self.vm is None:
            QMessageBox.information(self, "Vault", "Abra um Vault primeiro.")
            return
        old_pw, ok = QInputDialog.getText(self, "Senha atual", "Digite a senha atual:", QLineEdit.Password)
        if not ok or not old_pw:
            return
        new_pw, ok2 = QInputDialog.getText(self, "Nova senha", "Digite a nova senha:", QLineEdit.Password)
        if not ok2 or not new_pw:
            return
        confirm, ok3 = QInputDialog.getText(self, "Confirme a nova senha", "Repita a nova senha:", QLineEdit.Password)
        if not ok3 or new_pw != confirm:
            QMessageBox.warning(self, "Erro", "As senhas não coincidem.")
            return
        try:
            if hasattr(self.vm, "change_password"):
                self.vm.change_password(SecureMemory(old_pw), SecureMemory(new_pw))
            else:
                self.vm.rotate_keys(SecureMemory(new_pw))
            QMessageBox.information(self, "Sucesso", "Senha do Vault alterada com sucesso.")
        except WrongPassword:
            QMessageBox.critical(self, "Senha incorreta", "A senha atual está incorreta.")
        except Exception as e:
            QMessageBox.critical(self, "Erro", str(e))
        finally:
            old_pw = new_pw = confirm = ""

    def _open_vault(self):
        while True:
            if self.vm is None:
                pw, ok = QInputDialog.getText(self, "Vault", "Master-password:", QLineEdit.Password)
                if not ok or not pw:
                    return
                try:
                    vault_path = Config.default_path()
                    if vault_path.exists() and vault_path.stat().st_size == 0:
                        vault_path.unlink()
                    exists = vault_path.exists()
                    if not exists:
                        from vault import SecureMemory, StorageBackend, VaultManager
                        vm = VaultManager(StorageBackend(vault_path))
                        vm.create(SecureMemory(pw))
                        self.vm = vm
                        self.status.showMessage("Novo Vault criado com sucesso.", 8000)
                    else:
                        self.vm = open_or_init_vault(pw)
                        self.status.showMessage("Vault aberto com sucesso.", 8000)
                except CorruptVault:
                    if QMessageBox.question(
                        self,
                        "Vault corrompido",
                        "O arquivo vault3.dat parece corrompido.\nDeseja sobrescrevê-lo?",
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No,
                    ) == QMessageBox.Yes:
                        from vault import SecureMemory, StorageBackend, VaultManager
                        vm = VaultManager(StorageBackend(Config.default_path()))
                        vm.create(SecureMemory(pw))
                        self.vm = vm
                        self.status.showMessage("Novo Vault criado com sucesso.", 8000)
                    else:
                        return
                except WrongPassword:
                    QMessageBox.warning(self, "Vault", "Senha do Vault incorreta. Tente novamente.")
                    continue
                finally:
                    pw = ""
            if self.vm is not None:
                dlg = VaultDialog(self.vm, self)
                dlg.file_selected.connect(
                    lambda p: (
                        self.file_line.setText(p),
                        self._detect_algo(p),
                        self.status.showMessage("File selected from Vault."),
                    )
                )
                dlg.exec()
            break

    def _open_log(self):
        """Abre o arquivo de log no editor padrão, com flush e fallbacks."""
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
                    os.startfile(str(LOG_PATH))  # nosec B606
                    return
                except Exception:
                    pass

            # Unix
            for cmd in ("xdg-open", "open"):
                try:
                    import subprocess  # nosec B404
                    subprocess.Popen([cmd, str(LOG_PATH)])  # nosec B603
                    return
                except Exception:
                    continue  # nosec B112

            QMessageBox.information(self, "Log", f"Log file:\n{LOG_PATH}")
        except Exception as e:
            QMessageBox.warning(self, "Log", f"Não foi possível abrir o log:\n{e}\n\nCaminho: {LOG_PATH}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
