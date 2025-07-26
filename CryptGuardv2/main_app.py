#!/usr/bin/env python3
"""
CryptGuardv2 – secure GUI 2.6.3
"""
from __future__ import annotations

# ─── Standard library ────────────────────────────────────────────────────────
import sys, time, os, locale, zipfile, tempfile, shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Callable

if hasattr(sys.stdout, "reconfigure"):      # Windows → garantir UTF‑8
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

# ─── PySide6 / Qt ────────────────────────────────────────────────────────────
from PySide6.QtCore    import (
    Qt, Signal, QThread, QEvent, QPropertyAnimation, QEasingCurve, QTimer, QDate, QPoint
)
from PySide6.QtGui     import (
    QFont, QColor, QPalette, QIcon, QDragEnterEvent, QDropEvent, QDesktopServices,
    QPainter, QLinearGradient, QBrush
)
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QComboBox, QPushButton,
    QFileDialog, QHBoxLayout, QVBoxLayout, QProgressBar, QStatusBar, QMessageBox,
    QFrame, QCheckBox, QDateEdit, QToolButton
)

# ─── Projeto (backend) ───────────────────────────────────────────────────────
from crypto_core import encrypt as cg_encrypt, decrypt as cg_decrypt, SecurityProfile, LOG_PATH
from crypto_core.config  import STREAMING_THRESHOLD, MAGIC
from crypto_core.secure_bytes import SecureBytes          # ainda usado na leitura de meta
from crypto_core.utils   import secure_delete
from crypto_core.logger import logger     # ← novo

from json import loads
import json
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, message=".*utcfromtimestamp.*")

locale.setlocale(locale.LC_ALL, '')            # para formatação de velocidade

try:
    from zxcvbn import zxcvbn            # força da senha (opcional)
except ImportError:
    zxcvbn = None

ALGOS = [
    "AES-256-GCM",
    "AES-256-CTR",
    "ChaCha20-Poly1305",
    "XChaCha20-Poly1305",
]

# ════════════════════════════════════════════════════════════════════════════
#                              UI helpers
# ════════════════════════════════════════════════════════════════════════════
def human_speed(bytes_processed: int, elapsed_seconds: float) -> str:
    """Convert bytes and time to human-readable speed format."""
    if elapsed_seconds <= 0:
        return "– MB/s"
    
    speed_bps = bytes_processed / elapsed_seconds
    
    if speed_bps < 1024:
        return f"{speed_bps:.1f} B/s"
    elif speed_bps < 1024 * 1024:
        return f"{speed_bps / 1024:.1f} KB/s"
    elif speed_bps < 1024 * 1024 * 1024:
        return f"{speed_bps / (1024 * 1024):.1f} MB/s"
    else:
        return f"{speed_bps / (1024 * 1024 * 1024):.1f} GB/s"

class ClickableDateEdit(QDateEdit):
    """DateEdit que abre o calendário ao clicar no campo inteiro."""
    def mousePressEvent(self, event):
        # QDateEdit doesn't have showPopup method - need different approach
        if self.isEnabled() and self.calendarPopup():
            # We need to find the calendar button and click it
            for child in self.children():
                if isinstance(child, QToolButton):
                    child.click()
                    break
        # Always call the parent implementation
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
        self.setStyleSheet(f"""
            QPushButton {{
                background:{color}; color:white; border:none;
                border-radius:{self._radius}px; padding:9px 24px;
                font-weight:600; letter-spacing:0.3px;
            }}
            QPushButton:disabled {{background:#4e586e;}}
        """)

    # anima o botão crescendo/voltando
    def enterEvent(self, _: QEvent):
        self._update_css(self._hover)
        r = self.geometry(); r.adjust(-2, -2, 2, 2)
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
        g.setColorAt(0, QColor("#667eea")); g.setColorAt(1, QColor("#764ba2"))
        painter.fillRect(self.rect(), QBrush(g))

# ══════════════════════ Worker Thread ═══════════════════════════════════
class CryptoWorker(QThread):
    progress = Signal(int, float)
    finished = Signal(str)
    error = Signal(str)

    def __init__(self, func: Callable, src: str, pwd: str, profile: SecurityProfile, 
                 delete_flag: bool, extra: Optional[Dict] = None):
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
                self.pwd,                   # ← string bruta
                self.profile,
                progress_cb=progress_callback,
                **self.extra,
            )

            if not self.isInterruptionRequested():
                self.finished.emit(result)

        except InterruptedError:
            pass  # cancelado
        except Exception as e:
            logger.exception("CryptoWorker error")      # ← registra traceback
            self.error.emit(str(e))

# ══════════════════════ Main Window ══════════════════════════════════════
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptGuardv2 – secure 2.6.3")
        self.resize(800, 540)
        self.setMinimumSize(640, 440)
        self._apply_palette()
        self._build_ui()

    # ─────────────────────────── UI BUILD ────────────────────────────────
    def _build_ui(self):
        # ── Header ────────────────────────────────────────────────────────
        header = QFrame(); header.setFixedHeight(64)
        header.setStyleSheet(
            "QFrame{background:#263238;color:#ECEFF1;border-bottom:2px solid #37474F;}"
        )
        hlay = QHBoxLayout(header); hlay.setContentsMargins(18, 0, 18, 0)
        title = QLabel("🔐 CryptGuardv2", font=QFont("Inter", 20, QFont.DemiBold))
        title.setStyleSheet("color:white")
        hlay.addWidget(title); hlay.addStretch()

        # ── Sidebar ───────────────────────────────────────────────────────
        sidebar = QFrame(); sidebar.setFixedWidth(60)
        sidebar.setStyleSheet("background:#1E272E;")
        shield = QLabel("🛡️"); shield.setAlignment(Qt.AlignCenter)
        shield.setFont(QFont("Arial", 28))
        lay_sb = QVBoxLayout(sidebar); lay_sb.addStretch(); lay_sb.addWidget(shield)
        lay_sb.addStretch()

        # ── File picker / Drop zone ───────────────────────────────────────
        self.file_line = QLineEdit()
        self.file_line.setPlaceholderText("Drop a file or click Select…")
        self.file_line.setReadOnly(True)
        self.file_line.setAcceptDrops(False)
        self.setAcceptDrops(True)
        btn_pick = AccentButton("Select…"); btn_pick.clicked.connect(self._pick)
        lay_file = QHBoxLayout(); lay_file.addWidget(self.file_line); lay_file.addWidget(btn_pick)

        # ── Algorithm & security profile ─────────────────────────────────
        self.cmb_alg  = self._combo(ALGOS)
        self.cmb_prof = self._combo([p.name.title() for p in SecurityProfile])
        lay_alg  = self._field("Algorithm",        self.cmb_alg)
        lay_prof = self._field("Security profile", self.cmb_prof)

        # ── Expiration date & checkbox (mesma linha) ─────────────────────
        self.date_exp = ClickableDateEdit(QDate.currentDate())
        self.date_exp.setCalendarPopup(True)  # This enables the calendar popup button
        self.date_exp.setDisplayFormat("dd/MM/yyyy")
        self.date_exp.setMinimumDate(QDate.currentDate())
        self.date_exp.setEnabled(False)
        
        # Adicionar botão para abrir calendário explicitamente - use simpler approach
        cal_btn = QPushButton("📅")
        cal_btn.setMaximumWidth(30)
        cal_btn.setStyleSheet("background:#37474F;color:#ECEFF1;border:1px solid #455A64;")
        cal_btn.setEnabled(False)
        # Use manual click simulation instead of showPopup
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

        # ── Password & strength bar ───────────────────────────────────────
        self.pwd = QLineEdit(); self.pwd.setEchoMode(QLineEdit.Password)
        self.pwd.setPlaceholderText("Password…"); self.pwd.setMaximumWidth(280)
        self.pwd.textChanged.connect(self._update_strength)
        self.str_bar = QProgressBar(); self.str_bar.setMaximum(4); self.str_bar.setTextVisible(False)
        self.str_bar.setFixedWidth(140)
        lay_pwd = QHBoxLayout(); lay_pwd.addWidget(self.pwd); lay_pwd.addWidget(self.str_bar)

        # ── Options checkboxes ────────────────────────────────────────────
        self.chk_del = QCheckBox("Secure-delete input after operation")
        self.chk_archive = QCheckBox("Archive folder before encrypt (ZIP)")

        # ── Action buttons ────────────────────────────────────────────────
        self.btn_enc = AccentButton("Encrypt")
        self.btn_dec = AccentButton("Decrypt")
        self.btn_verify = AccentButton("Verify")
        self.btn_cancel = AccentButton("Cancel"); self.btn_cancel.setEnabled(False)
        self.btn_enc.clicked.connect(lambda: self._start(True))
        self.btn_dec.clicked.connect(lambda: self._start(False))
        self.btn_verify.clicked.connect(self._verify)
        self.btn_cancel.clicked.connect(self._cancel_current_task)
        lay_btn = QHBoxLayout()
        lay_btn.addWidget(self.btn_enc); lay_btn.addWidget(self.btn_dec)
        lay_btn.addWidget(self.btn_verify); lay_btn.addWidget(self.btn_cancel); lay_btn.addStretch()

        # ── Progress bar & speed ──────────────────────────────────────────
        self.prg = QProgressBar()
        self.prg.setValue(0); self.prg.setAlignment(Qt.AlignCenter)
        self.prg.setStyleSheet(
            "QProgressBar{background:#37474F;border:1px solid #263238;border-radius:5px;}"
            "QProgressBar::chunk{background:#29B6F6;}"
        )
        self.lbl_speed = QLabel("Speed: – MB/s")
        h_speed = QHBoxLayout(); h_speed.addStretch(); h_speed.addWidget(self.lbl_speed)

        # ── Central frame layout ─────────────────────────────────────────
        center = QVBoxLayout(); center.setSpacing(16); center.setContentsMargins(22, 22, 22, 22)
        center.addLayout(lay_file)
        center.addLayout(lay_alg); center.addLayout(lay_prof)
        center.addLayout(lay_exp)
        center.addLayout(lay_pwd)
        center.addWidget(self.chk_del, 0, Qt.AlignLeft)
        center.addWidget(self.chk_archive, 0, Qt.AlignLeft)
        center.addLayout(lay_btn)
        center.addWidget(self.prg)
        center.addLayout(h_speed); center.addStretch()
        central_frame = QFrame(); central_frame.setLayout(center)
        central_frame.setStyleSheet("background:#263238;")

        # ── Status bar ────────────────────────────────────────────────────
        self.status = QStatusBar(); self.status.showMessage("Ready.")
        log_btn = QPushButton("Log", clicked=lambda: QDesktopServices.openUrl(LOG_PATH.as_uri()))
        log_btn.setStyleSheet("background:transparent;color:#90A4AE;")
        self.status.addPermanentWidget(log_btn)

        # ── Main layout root ─────────────────────────────────────────────
        main = QVBoxLayout(self); main.setContentsMargins(0, 0, 0, 0)
        main.addWidget(header)
        body = QHBoxLayout(); body.setContentsMargins(0, 0, 0, 0)
        body.addWidget(sidebar); body.addWidget(central_frame, 1)
        main.addLayout(body); main.addWidget(self.status)

    # ───────────────────────── Palette & helpers ─────────────────────────
    def _apply_palette(self):
        pal = QPalette()
        pal.setColor(QPalette.Window, QColor("#20232a"))
        pal.setColor(QPalette.Base,   QColor("#2d3343"))
        pal.setColor(QPalette.Text,   QColor("#eceff4"))
        pal.setColor(QPalette.Button, QColor("#37474F"))
        pal.setColor(QPalette.ButtonText, QColor("#ECEFF1"))
        pal.setColor(QPalette.Highlight, QColor("#29B6F6"))
        pal.setColor(QPalette.HighlightedText, QColor("#fefeff"))
        QApplication.setPalette(pal)

    def _field(self, label: str, widget):
        lab = QLabel(label)
        lab.setFont(QFont("Inter", 10, QFont.Bold))
        lay = QHBoxLayout(); lay.addWidget(lab); lay.addWidget(widget); lay.addStretch()
        return lay

    def _combo(self, items):
        cmb = QComboBox(); cmb.addItems(items); cmb.setMaximumWidth(280)
        cmb.setStyleSheet(
            "QComboBox{background:#37474F;color:#ECEFF1;border:1px solid #455A64;"
            "border-radius:5px;padding:5px 10px;}"
            "QComboBox::drop-down{border:none;}"
            "QComboBox QAbstractItemView{background:#37474F;selection-background-color:#546E7A;color:white;}"
        )
        return cmb

    def _update_strength(self, txt: str):
        if not zxcvbn:
            return
        score = zxcvbn(txt)['score'] if txt else 0
        self.str_bar.setValue(score)
        colors = ["#d32f2f", "#f57c00", "#fbc02d", "#43a047", "#1b5e20"]
        self.str_bar.setStyleSheet(f"QProgressBar::chunk{{background:{colors[score]};}}")

    # ───────────────────────── Drag & drop events ────────────────────────
    def dragEnterEvent(self, e: QDragEnterEvent):   # noqa: N802
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e: QDropEvent):             # noqa: N802
        url = e.mimeData().urls()[0].toLocalFile()
        self.file_line.setText(url)
        self._detect_algo(url)
        self.status.showMessage("File/folder loaded via drag & drop")

    # ───────────────────────── File picker dialog ───────────────────────
    def _pick(self):
        msg = QMessageBox(self)
        msg.setWindowTitle("Select type")
        msg.setText("Choose what you want to encrypt / decrypt:")
        file_btn   = msg.addButton("File",   QMessageBox.AcceptRole)
        folder_btn = msg.addButton("Folder", QMessageBox.AcceptRole)
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

    # ───────────────────────── Detect algorithm from file ─────────────────
    def _detect_algo(self, path: str):
        """Detect algorithm from file header and set combo box accordingly."""
        try:
            src = Path(path)
            if not src.exists() or src.is_dir():
                return
            with src.open("rb") as f:
                f.seek(16)
                magic = f.read(4)
                if magic != MAGIC:
                    return  # Only detect for encrypted files
                tag_bytes = f.read(4)
                tag = tag_bytes.decode("ascii", errors="ignore")
            alg_map = {
                "AESG": 0,  # AES-256-GCM
                "ACTR": 1,  # AES-256-CTR
                "CH20": 2,  # ChaCha20-Poly1305
                "CHS3": 2,  # ChaCha20-Poly1305 (streaming)
                "XC20": 3,  # XChaCha20-Poly1305
                "XCS3": 3,  # XChaCha20-Poly1305 (streaming)
            }
            idx = alg_map.get(tag, -1)
            if idx >= 0:
                self.cmb_alg.setCurrentIndex(idx)
                self.status.showMessage(f"Detected algorithm: {self.cmb_alg.currentText()}")
        except Exception as e:
            self.status.showMessage(f"Could not detect algorithm: {e}")

    # ───────────────────────── Progress callbacks ───────────────────────
    def _progress(self, done: int, elapsed: float):
        if self._total_bytes:
            pct = min(int(done * 100 / self._total_bytes), 100)
            self.prg.setValue(pct)
            speed = human_speed(done, elapsed)
            self.lbl_speed.setText(f"Speed: {speed}")

    def _done(self, out_path: str):
        self.prg.setValue(100)
        # Handle auto-unpack and cleanup like the original implementation
        if hasattr(self, "_tmp_zip") and self._tmp_zip:
            Path(self._tmp_zip).unlink(missing_ok=True)
        
        # Auto-unpack ZIP files only for decrypt operations (not encrypt)
        if not self._is_encrypt and out_path.endswith('.zip') and zipfile.is_zipfile(out_path):
            dest_dir = Path(out_path).with_suffix('')  # Remove .zip
            
            # Create temp dir for safe extraction (avoid locks in final destination)
            with tempfile.TemporaryDirectory() as tmp_extract:
                tmp_path = Path(tmp_extract)
                try:
                    with zipfile.ZipFile(out_path, 'r') as zf:
                        for member in zf.infolist():
                            # Skip problematic files like desktop.ini (hidden/system files)
                            filename = member.filename.lower()
                            if (filename.endswith('desktop.ini') or 
                                filename.startswith('.') or 
                                filename.endswith('thumbs.db')):  # Skip common Windows system files
                                continue
                            
                            target = tmp_path / member.filename
                            target.parent.mkdir(parents=True, exist_ok=True)
                            
                            # Manual extraction with error handling
                            if not member.is_dir():
                                with zf.open(member) as source, open(target, "wb") as dest:
                                    shutil.copyfileobj(source, dest)
                    
                    # Move from temp to final destination (overwrite if necessary)
                    if dest_dir.exists():
                        if dest_dir.is_file():
                            dest_dir.unlink()  # Remove conflicting file
                        elif dest_dir.is_dir():
                            shutil.rmtree(dest_dir)  # Remove existing directory
                    
                    # Move entire extraction to final destination
                    try:
                        shutil.move(str(tmp_path), str(dest_dir))
                    except Exception as e:
                        QMessageBox.warning(self, "Move Error",
                                            f"Falha ao mover pasta extraída: {e}")
                        self.status.showMessage("❌ Move failed.", 10000)
                        return
                except PermissionError as e:
                    # Specific handling for permission issues (OneDrive sync, system files)
                    QMessageBox.warning(self, "Permission Error", 
                                      f"Failed to extract: {e}\n\n"
                                      "Try:\n"
                                      "• Pause OneDrive sync temporarily\n"
                                      "• Run as administrator\n"
                                      "• Extract to a location outside OneDrive")
                    self.status.showMessage("❌ Permission error during extraction.", 10000)
                    self.btn_cancel.setEnabled(False)
                    self._toggle(True)
                    return
                except Exception as e:
                    QMessageBox.critical(self, "Extraction Error", 
                                       f"Failed to extract ZIP: {e}")
                    self.status.showMessage(f"❌ Extraction failed: {e}", 10000)
                    self.btn_cancel.setEnabled(False)
                    self._toggle(True)
                    return
            
            Path(out_path).unlink(missing_ok=True)  # Remove ZIP after successful extraction
            out_path = str(dest_dir)  # Show folder in message
        
        if self.chk_del.isChecked():
            secure_delete(self._original_path, passes=1)
        QMessageBox.information(self, "Success",
                                f"Output file:\n{Path(out_path).name}")
        self.status.showMessage("✔️ Done.", 8000)
        self._toggle(True)

    def _err(self, msg: str):
        if getattr(self, "_tmp_zip", None):
            try: os.remove(self._tmp_zip)
            except Exception: pass
        friendly = self._translate_error(msg)
        QMessageBox.critical(self, "Erro", friendly)
        self.status.showMessage(f"Error: {friendly}", 10000)
        self._toggle(True)

    def _toggle(self, enabled: bool):
        for w in (self.btn_enc, self.btn_dec, self.btn_verify,
                  self.cmb_alg, self.cmb_prof, self.pwd, self.chk_del, self.chk_archive,
                  self.chk_exp, self.date_exp):
            w.setEnabled(enabled)
        if enabled:
            self.btn_cancel.setEnabled(False)
            self.prg.setMaximum(100)
            self.lbl_speed.setText("Speed: – MB/s")
            if hasattr(self, "worker"): del self.worker
        else:
            self.btn_cancel.setEnabled(True)

    # ───────────────────────── Cancelamento ──────────────
    def _cancel_current_task(self):
        if hasattr(self, "worker") and self.worker and self.worker.isRunning():
            self.worker.requestInterruption()
            # Aguarde até 5s para terminar graciosamente
            if not self.worker.wait(5000):  # ms
                # Timeout: Force quit (raro, mas seguro com QTimer)
                timer = QTimer(self)
                timer.timeout.connect(self.worker.quit)
                timer.start(100)  # Quit após pequeno delay
                self.worker.wait(1000)  # Aguarde mais 1s
            self.status.showMessage("⏹️ Operação cancelada.", 5000)
            self.btn_cancel.setEnabled(False)
            self._toggle(True)
            # Cleanup any temporary ZIP and trigger finish handlers
            if getattr(self, "_tmp_zip", None):
                try:
                    os.remove(self._tmp_zip)
                except Exception:
                    pass
            self.worker.finished.emit("")  # ensure downstream cleanup runs

    # ───────────────────────── Verify only ──────────────────────────────
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

    # ───────────────────────── Start encrypt/decrypt ────────────────────
    def _start(self, do_encrypt: bool):
        # Habilita seleção apenas se vamos **criptografar**
        self.cmb_alg.setEnabled(do_encrypt)
        
        path, pwd = self.file_line.text(), self.pwd.text()
        if not path:   return self.status.showMessage("Select a file first.")
        if not pwd:    return self.status.showMessage("Enter password.")
 
        self._is_encrypt = do_encrypt  # Track operation type for _done
        original_path = path
        src = path
        tmp_zip = None

        # Directory handling - prevent permission errors
        src_path = Path(src)
        if src_path.is_dir():
            if not do_encrypt:
                QMessageBox.warning(self, "Invalid Selection", 
                                  "Please select a file (not folder) for decrypt or verify operations.")
                return self.status.showMessage("Select a file for decrypt/verify.")
            if not self.chk_archive.isChecked():
                # Force archive for directories
                QMessageBox.information(self, "Auto-Archive", 
                                      "Folders require ZIP archiving for encryption. Enabling automatically.")
                self.chk_archive.setChecked(True)
 
        if do_encrypt and self.chk_archive.isChecked():
             try:
                 from crypto_core.utils import archive_folder
                 tmp_zip = archive_folder(src)
                 src = str(tmp_zip)
             except Exception as e:
                 return self.status.showMessage(f"Zip error: {e}")
 
        # Verify source file exists after potential ZIP creation
        try:
            src_size = Path(src).stat().st_size
        except FileNotFoundError:
            if tmp_zip:
                try: os.remove(tmp_zip)
                except Exception: pass
            return self.status.showMessage(f"Source file not found: {src}")
        except Exception as e:
            if tmp_zip:
                try: os.remove(tmp_zip)
                except Exception: pass
            return self.status.showMessage(f"Error accessing file: {e}")

        algo_idx = self.cmb_alg.currentIndex()
        profile  = list(SecurityProfile)[self.cmb_prof.currentIndex()]
        
        # ─── mapear seleção GUI → tag de 4 bytes/algoritmo ────────────────
        if algo_idx == 0:                                   # AES‑GCM
            alg_tag, stream = "AESG", False
        elif algo_idx == 1:                                 # AES‑CTR
            alg_tag, stream = "ACTR", False
        elif algo_idx == 2:                                 # ChaCha20‑Poly1305
            stream = src_size >= STREAMING_THRESHOLD
            alg_tag = "CHS3" if stream else "CH20"
        else:                                               # XChaCha20‑Poly1305
            stream = src_size >= STREAMING_THRESHOLD
            alg_tag = "XCS3" if stream else "XC20"

        if not do_encrypt:
            # Mostra qual algoritmo será usado
            alg_name = {
                "AESG": "AES‑256‑GCM",
                "ACTR": "AES‑256‑CTR",
                "CH20": "ChaCha20‑Poly1305",
                "CHS3": "ChaCha20‑Poly1305 (stream)",
                "XC20": "XChaCha20‑Poly1305",
                "XCS3": "XChaCha20‑Poly1305 (stream)",
            }.get(alg_tag, alg_tag)
            self.status.showMessage(f"Algoritmo detectado: {alg_name} — AAD verificada")

        delete_flag = self.chk_del.isChecked()
        self._tmp_zip = tmp_zip
        self._original_path = original_path

        # expiração
        extra: Dict[str, int] = {}
        if do_encrypt and self.chk_exp.isChecked():
            qd = self.date_exp.date()
            exp_dt = datetime(qd.year(), qd.month(), qd.day(), tzinfo=timezone.utc)
            if exp_dt.date() < datetime.now(timezone.utc).date():
                return self.status.showMessage("Expiration date cannot be in the past.")
            extra["expires_at"] = int(exp_dt.timestamp())

        # total bytes ----------------------------------------------------
        if do_encrypt:
            self._total_bytes = src_size
        else:
            meta_file = Path(src + ".meta")
            try:
                from crypto_core.metadata import decrypt_meta_json
                pwd_sb = SecureBytes(pwd.encode())
                meta = decrypt_meta_json(meta_file, pwd_sb)
                self._total_bytes = meta.get("size", src_size)
                pwd_sb.clear()
            except Exception:
                self._total_bytes = src_size

        self._toggle(False)
        # Set progress bar to indeterminate mode for key derivation
        self.prg.setMaximum(0)
        self.prg.setValue(0)
        self.status.showMessage("Deriving key (Argon2)…")
        
        # ─── preparar worker usando API unificada ─────────────────────────
        if do_encrypt:
            func = lambda path, pwd, prof, *, progress_cb=None, **kw: cg_encrypt(
                path,
                pwd,
                algo=alg_tag,
                streaming=stream,
                profile=prof,
                progress_cb=progress_cb,
                **kw,
            )
        else:
            func = lambda path, pwd, prof_hint, *, progress_cb=None, **kw: cg_decrypt(
                path,
                pwd,
                progress_cb=progress_cb,
                profile_hint=prof_hint,
                **kw,
            )

        self.worker = CryptoWorker(
            func,
            src,
            pwd,
            profile,
            delete_flag,
            extra=extra,
        )
        self.worker.progress.connect(self._progress)
        self.worker.finished.connect(self._done)
        self.worker.error.connect(self._err)
        self._t_start = time.time()
        self.worker.start(); self.pwd.clear()

    # Add a new helper method to show calendar popup
    def _show_calendar_popup(self):
        """Helper method to show calendar popup when button is clicked."""
        if self.date_exp.isEnabled():
            # Find calendar button in the date edit widget and click it
            for child in self.date_exp.children():
                if isinstance(child, QPushButton) or "QToolButton" in child.metaObject().className():
                    child.click()
                    return
            # Fallback: click directly on the widget to try to activate it
            self.date_exp.setFocus()
    
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
