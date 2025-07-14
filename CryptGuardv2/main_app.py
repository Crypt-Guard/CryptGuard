#!/usr/bin/env python3
"""
CryptGuard v2 – Modern GUI

A full‑featured PySide6 interface inspired by KeyGuard’s polished look and the
Wifi‑Share web app’s vivid gradients.  Highlights:
- Adaptive dark / light theme with a toggle
- Animated gradient header
- Drop‑zone with ripple highlight
- Password strength meter (zxcvbn)
- Optional secure‑delete checkbox
- Live MB/s throughput readout next to progress bar
- Responsive layout (works ≥ 640 × 400)

Back‑end hooks remain IDENTICAL – the worker still calls encrypt/decrypt
functions from crypto_core.
"""
from __future__ import annotations

import sys, time, os, secrets
from pathlib import Path
from typing import Optional

from PySide6.QtCore    import (Qt, Signal, QThread, QSize, QPoint, QEvent,
                               QPropertyAnimation, QEasingCurve)
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
from crypto_core.config import STREAMING_THRESHOLD
from json import loads
import json

try:
    from zxcvbn import zxcvbn
except ImportError:
    zxcvbn = None

ALGOS = ["AES-256-GCM", "AES-256-CTR", "ChaCha20-Poly1305"]

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
        self.setWindowTitle("CryptGuardv2 – secure")
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
        title = QLabel("🔐 CryptGuard v2", font=QFont("Inter", 20, QFont.DemiBold))
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
        self.chk_del     = QCheckBox("Secure-delete original after encrypt")
        self.chk_archive = QCheckBox("Archive folder before encrypt (ZIP)")
        
        # Action buttons
        self.btn_enc = AccentButton("Encrypt")
        self.btn_dec = AccentButton("Decrypt")
        self.btn_enc.clicked.connect(lambda: self._start(True))
        self.btn_dec.clicked.connect(lambda: self._start(False))
        lay_btn = QHBoxLayout(); lay_btn.addWidget(self.btn_enc); lay_btn.addWidget(self.btn_dec); lay_btn.addStretch()

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
 
        src = path
        tmp_zip = None
 
        if encrypt and self.chk_archive.isChecked():
             try:
                 from crypto_core.utils import archive_folder
                 tmp_zip = archive_folder(src)
                 src = str(tmp_zip)
             except Exception as e:
                 return self.status.showMessage(f"Zip error: {e}")
 
        algo_idx = self.cmb_alg.currentIndex()
        profile  = list(SecurityProfile)[self.cmb_prof.currentIndex()]
        # choose encrypt/decrypt funcs
        if algo_idx == 0:
            func_enc, func_dec = encrypt_aes, decrypt_aes
        elif algo_idx == 1:
            func_enc, func_dec = encrypt_ctr, decrypt_ctr
        else:
            size = Path(src).stat().st_size
            stream       = size >= STREAMING_THRESHOLD
            func_enc     = encrypt_chacha_stream if stream else encrypt_chacha
            func_dec     = decrypt_chacha_stream if stream else decrypt_chacha
 
        delete_flag = self.chk_del.isChecked() if encrypt else False
        self._tmp_zip = tmp_zip
        # total bytes ----------------------------------------------------
        if encrypt:
            self._total_bytes = Path(src).stat().st_size
        else:
            meta_file = Path(src + ".meta")
            try:
                from crypto_core.metadata import decrypt_meta_json
                meta = decrypt_meta_json(meta_file, pwd)
                self._total_bytes = meta.get("size", Path(src).stat().st_size)
            except Exception:
                self._total_bytes = Path(src).stat().st_size

        self._toggle(False)
        self.prg.setValue(0)
        func = func_enc if encrypt else func_dec
        self.worker = CryptoWorker(func, src, pwd, profile, delete_flag)
        self.worker.progress.connect(self._progress)
        self.worker.finished.connect(self._done)
        self.worker.error.connect(self._err)
        self._t_start = time.time()
        self.worker.start(); self.pwd.clear()

    def _progress(self, done: int, elapsed: float):
        pct = int(min(done * 100 / self._total_bytes, 99))
        self.prg.setValue(pct)
        speed = (done / elapsed) / 1_048_576 if elapsed else 0.0
        self.lbl_speed.setText(f"Speed: {speed:,.1f} MB/s")
 
    def _done(self, out_path: str):
        self.prg.setValue(100)                       # garante 100 %
        if hasattr(self, "_tmp_zip") and self._tmp_zip:
            Path(self._tmp_zip).unlink(missing_ok=True)
        QMessageBox.information(self, "Success", f"Output file:\n{out_path}")
        self.status.showMessage("✔️ Done.", 8000)
        self._toggle(True)

    def _err(self, msg: str):
        if getattr(self, "_tmp_zip", None):
            try: os.remove(self._tmp_zip)
            except Exception: pass
        QMessageBox.critical(self, "Error", msg)
        self.status.showMessage(f"Error: {msg}", 10000)
        self._toggle(True)

    def _toggle(self, enable: bool):
        for w in (self.btn_enc, self.btn_dec, self.cmb_alg, self.cmb_prof, self.chk_del):
            w.setEnabled(enable)

# ══════════════════════ main ═══════════════════════════════════════════════
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow(); win.show()
    sys.exit(app.exec())
