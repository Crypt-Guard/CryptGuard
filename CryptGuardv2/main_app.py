#!/usr/bin/env python3
"""
CryptGuardv2 – Modern GUI

"""
from __future__ import annotations

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

import sys, time, os, secrets, locale
import zipfile  # Add zipfile import
import tempfile  # Add tempfile import
import shutil   # Add shutil import
from pathlib import Path
from typing import Optional

from PySide6.QtCore    import (Qt, Signal, QThread, QSize, QPoint, QEvent,
                               QPropertyAnimation, QEasingCurve, QTimer)
from PySide6.QtGui     import (QFont, QColor, QPalette, QIcon, QPainter,
                               QLinearGradient, QBrush, QDesktopServices)
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QComboBox, QPushButton, QFileDialog,
    QHBoxLayout, QVBoxLayout, QProgressBar, QStatusBar, QMessageBox, QFrame,
    QCheckBox
)

# ─── crypto_core back‑end ───────────────────────────────────────────────
from crypto_core import (
    encrypt_aes, decrypt_aes, encrypt_ctr, decrypt_ctr,
    encrypt_chacha, decrypt_chacha,
    encrypt_chacha_stream, decrypt_chacha_stream,
    SecurityProfile, LOG_PATH
)
from crypto_core.secure_bytes import SecureBytes
# Novo módulo XChaCha (adicionado ao projeto conforme instruções)
from crypto_core.file_crypto_xchacha import (
    encrypt_file as encrypt_xchacha,
    decrypt_file as decrypt_xchacha,
)
from crypto_core.file_crypto_xchacha_stream import (
    encrypt_file as encrypt_xchacha_stream,
    decrypt_file as decrypt_xchacha_stream,
)
from crypto_core.config import STREAMING_THRESHOLD
from json import loads
import json

locale.setlocale(locale.LC_ALL, '')            # para formatação de velocidade

try:
    from zxcvbn import zxcvbn
except ImportError:
    zxcvbn = None

ALGOS = ["AES-256-GCM",
         "AES-256-CTR",
         "ChaCha20-Poly1305",
         "XChaCha20-Poly1305"]  # novo item

# ══════════════════════ worker ═══════════════════════════════════════════
class CryptoWorker(QThread):
    progress = Signal(int, float)  # bytes, elapsed
    finished = Signal(str)
    error    = Signal(str)

    def __init__(self, func, src: str, pwd: str, profile: SecurityProfile,
                 delete_orig: bool):
        super().__init__()
        self.func, self.src, self.pwd, self.profile = func, src, pwd, profile
        self.delete_orig = delete_orig

    def run(self):
        from crypto_core.utils import secure_delete
        from crypto_core.logger import logger
        start = time.time()
        try:
            out = self.func(
                self.src, self.pwd, self.profile,
                progress_cb=lambda b: self.progress.emit(b, time.time() - start)
            )
            if self.delete_orig:
                secure_delete(self.src, passes=1)
            logger.info("Done in %.2f s -> %s", time.time() - start, out)
            self.finished.emit(out)
        except Exception as e:  # pylint: disable=broad-except
            logger.exception("Worker error: %s", e)
            self.error.emit(str(e))

# ══════════════════════ fancy widgets ═══════════════════════════════════
class AccentButton(QPushButton):
    def __init__(self, txt: str):
        super().__init__(txt)
        self.setCursor(Qt.PointingHandCursor)
        self._base  = "#536dfe"
        self._hover = "#7c9dff"
        self._radius = 9
        self._update_css(self._base)
        self._anim = QPropertyAnimation(self, b"geometry", self)
        self._anim.setDuration(150)
        self._anim.setEasingCurve(QEasingCurve.OutQuad)

    def enterEvent(self, e):
        self._update_css(self._hover)
        r = self.geometry(); r.adjust(-2, -2, 2, 2)
        self._animate(r)
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._update_css(self._base)
        r = self.geometry().adjusted(2, 2, -2, -2)
        self._animate(r)
        super().leaveEvent(e)

    def _update_css(self, color):
        self.setStyleSheet(f"""
            QPushButton {{
                background:{color}; color:white; border:none;
                border-radius:{self._radius}px; padding:9px 24px;
                font-weight:600; letter-spacing:0.3px;
            }}
            QPushButton:disabled {{background:#4e586e;}}
        """)

    def _animate(self, rect):
        self._anim.stop(); self._anim.setStartValue(self.geometry()); self._anim.setEndValue(rect); self._anim.start()

class GradientHeader(QFrame):
    def paintEvent(self, evt):
        painter = QPainter(self)
        g = QLinearGradient(QPoint(0, 0), QPoint(self.width(), 0))
        g.setColorAt(0, QColor("#667eea")); g.setColorAt(1, QColor("#764ba2"))
        painter.fillRect(self.rect(), QBrush(g))

# ══════════════════════ Main Window ══════════════════════════════════════
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptGuardv2 – secure 2.6.1")
        self.resize(800, 540); self.setMinimumSize(640, 440)
        self._total_bytes = 0
        self.dark = True
        self._apply_palette()
        self._build_ui()

    # ── UI ------------------------------------------------------------------
    def _build_ui(self):
        # Header with gradient + title + theme toggle
        header = QFrame()
        header.setFixedHeight(64)
        header.setStyleSheet(
            """
            QFrame {
                background: #263238;
                color: #ECEFF1;
                border-bottom: 2px solid #37474F;
            }
            """
        )
        hlay = QHBoxLayout(header); hlay.setContentsMargins(18, 0, 18, 0)
        title = QLabel("🔐 CryptGuardv2", font=QFont("Inter", 20, QFont.DemiBold))
        title.setStyleSheet("color:white")
        hlay.addWidget(title)
        hlay.addStretch()

        # Sidebar (icon only)
        sidebar = QFrame(); sidebar.setFixedWidth(60)
        sidebar.setStyleSheet("background:#1E272E;")
        shield = QLabel("🛡️"); shield.setAlignment(Qt.AlignCenter); shield.setFont(QFont("Arial", 28))
        lay_sb = QVBoxLayout(sidebar); lay_sb.addStretch(); lay_sb.addWidget(shield); lay_sb.addStretch()

        # File picker / drop zone ------------------------------------------------
        self.file_line = QLineEdit(); self.file_line.setPlaceholderText("Drop a file or click Select…")
        self.file_line.setReadOnly(True); self.file_line.setAcceptDrops(False)
        self.setAcceptDrops(True)
        btn_pick = AccentButton("Select…")
        btn_pick.clicked.connect(self._pick)
        lay_file = QHBoxLayout(); lay_file.addWidget(self.file_line); lay_file.addWidget(btn_pick)

        # Algorithm + profile combos
        self.cmb_alg  = self._combo(ALGOS)
        self.cmb_prof = self._combo([p.name.title() for p in SecurityProfile])
        lay_alg  = self._field("Algorithm", self.cmb_alg)
        lay_prof = self._field("Security profile", self.cmb_prof)

        # Password + strength
        self.pwd = QLineEdit(); self.pwd.setEchoMode(QLineEdit.Password); self.pwd.setPlaceholderText("Password…"); self.pwd.setMaximumWidth(280)
        self.pwd.textChanged.connect(self._update_strength)
        self.str_bar = QProgressBar(); self.str_bar.setMaximum(4); self.str_bar.setTextVisible(False); self.str_bar.setFixedWidth(140)
        lay_pwd = QHBoxLayout(); lay_pwd.addWidget(self.pwd); lay_pwd.addWidget(self.str_bar)

        # Secure delete checkbox
        self.chk_del     = QCheckBox("Secure-delete input after operation")
        self.chk_archive = QCheckBox("Archive folder before encrypt (ZIP)")
        
        # Action buttons
        self.btn_enc    = AccentButton("Encrypt")
        self.btn_dec    = AccentButton("Decrypt")
        self.btn_verify = AccentButton("Verify")
        self.btn_cancel = AccentButton("Cancel")       # botão moderno
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self._cancel_current_task)
        self.btn_enc.clicked.connect(lambda: self._start(True))
        self.btn_dec.clicked.connect(lambda: self._start(False))
        self.btn_verify.clicked.connect(self._verify)
        lay_btn = QHBoxLayout()
        lay_btn.addWidget(self.btn_enc)
        lay_btn.addWidget(self.btn_dec)
        lay_btn.addWidget(self.btn_verify)
        lay_btn.addWidget(self.btn_cancel)
        lay_btn.addStretch()

        # Progress + speed
        self.prg = QProgressBar()
        self.prg.setValue(0)
        self.prg.setAlignment(Qt.AlignCenter)  # center text
        self.prg.setStyleSheet(
            "QProgressBar{background:#37474F;border:1px solid #263238;border-radius:5px;text-align:center;}"
            "QProgressBar::chunk{background:#29B6F6;}"
        )
        self.lbl_speed = QLabel("Speed: – MB/s")
        h_speed = QHBoxLayout(); h_speed.addStretch(); h_speed.addWidget(self.lbl_speed)
        lay_prog = QHBoxLayout(); lay_prog.addWidget(self.prg, 1)
        
        # Central layout
        center = QVBoxLayout(); center.setSpacing(16); center.setContentsMargins(22,22,22,22)
        center.addLayout(lay_file)
        center.addLayout(lay_alg); center.addLayout(lay_prof)
        center.addLayout(lay_pwd); center.addWidget(self.chk_del, 0, Qt.AlignLeft)
        center.addWidget(self.chk_archive, 0, Qt.AlignLeft)
        center.addLayout(lay_btn)
        center.addLayout(lay_prog)
        center.addLayout(h_speed)
        center.addStretch()
        central_frame = QFrame(); central_frame.setLayout(center); central_frame.setStyleSheet("background:#263238;")

        # Status bar
        self.status = QStatusBar(); self.status.showMessage("Ready.")
        log_btn = QPushButton("Log", clicked=lambda: QDesktopServices.openUrl(LOG_PATH.as_uri()))
        log_btn.setStyleSheet("background:transparent;color:#90A4AE;")
        self.status.addPermanentWidget(log_btn)

        # Main layout
        main = QVBoxLayout(self); main.setContentsMargins(0, 0, 0, 0)
        main.addWidget(header)
        body = QHBoxLayout(); body.setContentsMargins(0, 0, 0, 0)
        body.addWidget(sidebar); body.addWidget(central_frame, 1)
        main.addLayout(body); main.addWidget(self.status)

    # ── Event overrides for drag & drop ----------------------------------------
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        url = e.mimeData().urls()[0].toLocalFile()
        self.file_line.setText(url)
        self.status.showMessage("File/Folder loaded via drag & drop")

    # ── Helpers -----------------------------------------------------------------
    def _field(self, lbl: str, widget):
        lab = QLabel(lbl); lab.setFont(QFont("Inter", 10, QFont.Bold))
        hl = QHBoxLayout(); hl.addWidget(lab); hl.addWidget(widget); hl.addStretch(); return hl

    def _combo(self, items):
        cmb = QComboBox(); cmb.addItems(items); cmb.setMaximumWidth(280)
        cmb.setStyleSheet("""QComboBox{background:#37474F;color:#ECEFF1;border:1px solid #455A64;border-radius:5px;padding:5px 10px;} QComboBox::drop-down{border:none;} QComboBox QAbstractItemView{background:#37474F;selection-background-color:#546E7A;color:white;}""")
        return cmb

    def _apply_palette(self):
        pal = QPalette()
        if self.dark:
            pal.setColor(QPalette.Window, QColor("#20232a"))
            pal.setColor(QPalette.Base,   QColor("#2d3343"))
            pal.setColor(QPalette.Text,   QColor("#eceff4"))
            pal.setColor(QPalette.Button, QColor("#37474F"))
            pal.setColor(QPalette.ButtonText, QColor("#ECEFF1"))
            pal.setColor(QPalette.Highlight, QColor("#29B6F6"))
            pal.setColor(QPalette.HighlightedText, QColor("#fefeff"))
        else:
            pal = QApplication.style().standardPalette()
        QApplication.setPalette(pal)

    def _update_strength(self, txt):
        if not zxcvbn: return
        score = zxcvbn(txt)['score'] if txt else 0
        self.str_bar.setValue(score)
        colors = ["#d32f2f","#f57c00","#fbc02d","#43a047","#1b5e20"]
        chunk_style = f"QProgressBar::chunk{{background:{colors[score]};}}"
        self.str_bar.setStyleSheet(chunk_style)

    # ── File pick ---------------------------------------------------------------
    # ----------------------------------------------------------------- pick
    def _pick(self):
        """Dialogo de seleção: FILE ou FOLDER com rótulos claros."""
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
            f, _ = QFileDialog.getOpenFileName(self, "Choose file", "", "All (*.*)")
            if f:
                self.file_line.setText(f)
                self.status.showMessage("File selected.")
        else:
            folder = QFileDialog.getExistingDirectory(self, "Choose folder", "")
            if folder:
                self.file_line.setText(folder)
                self.status.showMessage("Folder selected.")

    # ── Start process -----------------------------------------------------------
    def _start(self, encrypt: bool):
        path, pwd = self.file_line.text(), self.pwd.text()
        if not path:   return self.status.showMessage("Select a file first.")
        if not pwd:    return self.status.showMessage("Enter password.")
 
        self._is_encrypt = encrypt  # Track operation type for _done
        pwd_sb = SecureBytes(pwd.encode())
        original_path = path
        src = path
        tmp_zip = None

        # Directory handling - prevent permission errors
        src_path = Path(src)
        if src_path.is_dir():
            if not encrypt:
                QMessageBox.warning(self, "Invalid Selection", 
                                  "Please select a file (not folder) for decrypt or verify operations.")
                return self.status.showMessage("Select a file for decrypt/verify.")
            if not self.chk_archive.isChecked():
                # Force archive for directories
                QMessageBox.information(self, "Auto-Archive", 
                                      "Folders require ZIP archiving for encryption. Enabling automatically.")
                self.chk_archive.setChecked(True)
 
        if encrypt and self.chk_archive.isChecked():
             try:
                 from crypto_core.utils import archive_folder
                 tmp_zip = archive_folder(src)
                 src = str(tmp_zip)
             except Exception as e:
                 pwd_sb.clear()
                 return self.status.showMessage(f"Zip error: {e}")
 
        algo_idx = self.cmb_alg.currentIndex()
        profile  = list(SecurityProfile)[self.cmb_prof.currentIndex()]
        # Escolher funções de (des)criptografia conforme algoritmo
        if algo_idx == 0:                       # AES‑GCM
            func_enc, func_dec = encrypt_aes, decrypt_aes
        elif algo_idx == 1:                     # AES‑CTR
            func_enc, func_dec = encrypt_ctr, decrypt_ctr
        elif algo_idx == 2:                     # ChaCha20‑Poly1305
            size = Path(src).stat().st_size
            stream       = size >= STREAMING_THRESHOLD
            func_enc     = encrypt_chacha_stream if stream else encrypt_chacha
            func_dec     = decrypt_chacha_stream if stream else decrypt_chacha
        else:                                   # XChaCha20‑Poly1305
            size = Path(src).stat().st_size
            stream = size >= STREAMING_THRESHOLD
            func_enc = (encrypt_xchacha_stream if stream
                        else encrypt_xchacha)
            func_dec = (decrypt_xchacha_stream if stream
                        else decrypt_xchacha)
 
        delete_flag = self.chk_del.isChecked()
        self._tmp_zip = tmp_zip
        self._original_path = original_path
        # total bytes ----------------------------------------------------
        if encrypt:
            self._total_bytes = Path(src).stat().st_size
        else:
            meta_file = Path(src + ".meta")
            try:
                from crypto_core.metadata import decrypt_meta_json
                meta = decrypt_meta_json(meta_file, pwd_sb)
                self._total_bytes = meta.get("size", Path(src).stat().st_size)
            except Exception:
                self._total_bytes = Path(src).stat().st_size
            finally:
                pwd_sb.clear()

        self._toggle(False)
        # Set progress bar to indeterminate mode for key derivation
        self.prg.setMaximum(0)
        self.prg.setValue(0)
        self.status.showMessage("Deriving key (Argon2)…")
        
        func = func_enc if encrypt else func_dec
        self.worker = CryptoWorker(func, src, pwd, profile, delete_flag)
        self.worker.progress.connect(self._progress)
        self.worker.finished.connect(self._done)
        self.worker.error.connect(self._err)
        self._t_start = time.time()
        self.worker.start(); self.pwd.clear()
        self.btn_cancel.setEnabled(True)

    # ────────────── Cancelamento ──────────────
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

    def _progress(self, done: int, elapsed: float):
        # Switch back to normal progress mode on first progress update
        if self.prg.maximum() == 0:
            self.prg.setMaximum(100)
            self.status.showMessage("Processing…")
        
        pct = round(done * 100 / self._total_bytes)
        if pct > 100:
            pct = 100
        self.prg.setValue(pct)

        speed = (done / elapsed) / 1_048_576 if elapsed else 0.0
        self.lbl_speed.setText(
            f"Speed: {locale.format_string('%.1f', speed, grouping=True)} MB/s"
        )
 
    def _done(self, out_path: str):
        self.prg.setValue(100)                       # garante 100 %
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
            from crypto_core.utils import secure_delete
            secure_delete(self._original_path, passes=1)
        QMessageBox.information(self, "Success",
                                f"Output file:\n{Path(out_path).name}")
        self.status.showMessage("✔️ Done.", 8000)
        self.btn_cancel.setEnabled(False)
        self._toggle(True)

    def _err(self, msg: str):
        if getattr(self, "_tmp_zip", None):
            try: os.remove(self._tmp_zip)
            except Exception: pass
        friendly = self._translate_error(msg)
        QMessageBox.critical(self, "Erro", friendly)
        self.status.showMessage(f"Error: {friendly}", 10000)
        self.btn_cancel.setEnabled(False)
        self._toggle(True)

    def _toggle(self, enable: bool):
        for w in (self.btn_enc, self.btn_dec, self.btn_verify, self.cmb_alg,
                  self.cmb_prof, self.chk_del):
            w.setEnabled(enable)
        if hasattr(self, "btn_cancel"):
            self.btn_cancel.setEnabled(not enable)

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

# ══════════════════════ main ═══════════════════════════════════════════════
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow(); win.show()
    sys.exit(app.exec())
