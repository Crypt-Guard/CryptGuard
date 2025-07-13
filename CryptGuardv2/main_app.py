#!/usr/bin/env python3
import sys, time
from pathlib import Path
from PySide6.QtCore    import Qt, Signal, QThread, QEasingCurve, QPropertyAnimation
from PySide6.QtGui     import QFont, QDesktopServices, QIcon, QColor, QPalette
from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QComboBox, QPushButton, QFileDialog,
    QHBoxLayout, QVBoxLayout, QProgressBar, QStatusBar, QMessageBox, QFrame
)

# ─────────── back-end ──────────────────────────────────────────────────────────────
from crypto_core import (
    encrypt_aes, decrypt_aes,
    encrypt_chacha, decrypt_chacha,
    encrypt_chacha_stream, decrypt_chacha_stream,
    SecurityProfile, LOG_PATH
)
from crypto_core.config import STREAMING_THRESHOLD
from json import loads
from pathlib import Path as PathLib

ALGOS = ["AES-256-GCM", "ChaCha20-Poly1305"]

# ─────────── Worker thread real ────────────────────────────────────────────────────
class CryptoWorker(QThread):
    progress = Signal(int, float)        # bytes, elapsed
    finished = Signal(str)
    error    = Signal(str)

    def __init__(self, func, path:str, pwd:str, profile:SecurityProfile):
        super().__init__()
        self.func, self.path, self.pwd, self.profile = func, path, pwd, profile

    def run(self):
        start = time.time()
        try:
            out = self.func(
                self.path, self.pwd, self.profile,
                progress_cb=lambda b: self.progress.emit(b, time.time()-start)
            )
            # Log successful operation
            from crypto_core.logger import logger
            logger.info("Operação concluída em %.2f s -> %s", time.time()-start, out)
            self.finished.emit(out)
        except Exception as e:           # pylint: disable=broad-except
            self.error.emit(str(e))

# ─────────── Widgets utilitários ───────────────────────────────────────────────────
class AccentButton(QPushButton):
    """Botão com animação hover e cantos arredondados."""
    _BASE  = "#3F51B5"
    _HOVER = "#5C6BC0"

    def __init__(self, txt:str):
        super().__init__(txt)
        self.setCursor(Qt.PointingHandCursor)
        self._css(self._BASE)
        self._anim = QPropertyAnimation(self, b"geometry", self)
        self._anim.setDuration(140); self._anim.setEasingCurve(QEasingCurve.OutQuad)

    # ----- animação hover
    def enterEvent(self, e):
        self._css(self._HOVER)
        r = self.geometry(); r.adjust(-2,-2,2,2)
        self._animate(r)
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._css(self._BASE)
        r = self.geometry().adjusted(2,2,-2,-2)
        self._animate(r)
        super().leaveEvent(e)

    def _css(self, color):  # estilo inline simplificado
        self.setStyleSheet(f"""
            QPushButton {{
                background:{color}; color:white;
                border:none; border-radius:7px; padding:8px 22px;
                font-weight:600;
            }}
            QPushButton:disabled {{background:#546E7A;}}
        """)

    def _animate(self, rect):
        self._anim.stop()
        self._anim.setStartValue(self.geometry())
        self._anim.setEndValue(rect)
        self._anim.start()

class Header(QFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("Header")
        icon = QLabel("🔐");  icon.setFont(QFont("Arial", 24))
        title = QLabel("CryptGuardv2")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        lay = QHBoxLayout(self); lay.setContentsMargins(16,8,16,8)
        lay.addWidget(icon, 0, Qt.AlignVCenter)
        lay.addWidget(title, 1, Qt.AlignVCenter)
        self.setStyleSheet("""
            #Header {background:#263238; color:#ECEFF1;
                     border-bottom:2px solid #37474F;}
        """)

# ─────────── Janela principal ──────────────────────────────────────────────────────
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptGuardv2 – v2.3 secure")
        self.resize(740, 500); self.setMinimumSize(620, 440)
        self._apply_dark_palette()
        self._build_ui()
        self._total_bytes = 0  # Track total bytes for progress calculation

    # ----- UI ----------------------------------------------------------------------
    def _build_ui(self):
        header = Header()

        # ---- Sidebar minimalista
        sidebar = QFrame(); sidebar.setFixedWidth(60)
        sidebar.setStyleSheet("background:#1E272E;")
        logo = QLabel("🛡️"); logo.setAlignment(Qt.AlignCenter); logo.setFont(QFont("Arial", 26))
        lay_sb = QVBoxLayout(sidebar); lay_sb.addStretch(); lay_sb.addWidget(logo); lay_sb.addStretch()

        # ---- widgets principais ----------------------------------------------------
        # arquivo
        self.file_line = QLineEdit(); self.file_line.setReadOnly(True)
        self.file_line.setPlaceholderText("Nenhum arquivo selecionado…")
        btn_file = AccentButton("Selecionar…"); btn_file.clicked.connect(self._pick)
        h_file = QHBoxLayout(); h_file.addWidget(self.file_line); h_file.addWidget(btn_file)

        # algoritmo
        self.cmb_alg = self._combo(ALGOS)
        grp_alg = self._field("Algoritmo", self.cmb_alg)

        # perfil
        profiles = [p.name.title() for p in SecurityProfile]
        self.cmb_prof = self._combo(profiles)
        grp_prof = self._field("Perfil de segurança", self.cmb_prof)

        # senha
        self.pwd = QLineEdit(); self.pwd.setEchoMode(QLineEdit.Password)
        self.pwd.setPlaceholderText("Senha…"); self.pwd.setMaximumWidth(260)

        # botões
        self.btn_enc = AccentButton("Criptografar")
        self.btn_dec = AccentButton("Descriptografar")
        self.btn_enc.clicked.connect(lambda: self._start(True))
        self.btn_dec.clicked.connect(lambda: self._start(False))
        h_btns = QHBoxLayout(); h_btns.addWidget(self.btn_enc); h_btns.addWidget(self.btn_dec); h_btns.addStretch()

        # progresso
        self.prg = QProgressBar(); self.prg.setValue(0)
        self.prg.setStyleSheet("""
            QProgressBar {background:#37474F; border:1px solid #263238;
                          border-radius:5px; text-align:center;}
            QProgressBar::chunk {background:#29B6F6;}
        """)
        self.lbl_time = QLabel("Tempo: – s")

        # ---- layout central -------------------------------------------------------
        center = QVBoxLayout(); center.setSpacing(14); center.setContentsMargins(18,18,18,18)
        center.addLayout(h_file)
        center.addLayout(grp_alg); center.addLayout(grp_prof)
        center.addWidget(self.pwd, 0, Qt.AlignLeft)
        center.addLayout(h_btns)
        center.addWidget(self.prg); center.addWidget(self.lbl_time, 0, Qt.AlignRight)
        center.addStretch()

        central_container = QFrame(); central_container.setStyleSheet("background:#263238;")
        central_container.setLayout(center)

        # status
        self.status = QStatusBar(); self.status.showMessage("Pronto.")
        btn_log = QPushButton(QIcon.fromTheme("document-open"), "Log")
        btn_log.setStyleSheet("background:transparent; color:#90A4AE;")
        btn_log.clicked.connect(lambda: QDesktopServices.openUrl(LOG_PATH.as_uri()))
        self.status.addPermanentWidget(btn_log)

        # ---- layout global --------------------------------------------------------
        main = QVBoxLayout(self); main.setContentsMargins(0,0,0,0)
        main.addWidget(header)
        body = QHBoxLayout(); body.setContentsMargins(0,0,0,0)
        body.addWidget(sidebar)
        body.addWidget(central_container, 1)
        main.addLayout(body)
        main.addWidget(self.status)

    # ----- field helpers -----------------------------------------------------------
    def _field(self, label:str, widget:QWidget):
        lbl = QLabel(label); lbl.setFont(QFont("Arial", 10, QFont.Bold))
        lay = QHBoxLayout(); lay.addWidget(lbl); lay.addWidget(widget); lay.addStretch()
        return lay

    def _combo(self, items):
        cmb = QComboBox(); cmb.addItems(items); cmb.setMaximumWidth(260)
        cmb.setStyleSheet("""
            QComboBox {background:#37474F; color:#ECEFF1; border:1px solid #455A64;
                       border-radius:4px; padding:4px 8px;}
            QComboBox::drop-down {border:none;}
            QComboBox QAbstractItemView {background:#37474F;
                       selection-background-color:#546E7A; color:white;}
        """)
        return cmb

    # ----- actions -----------------------------------------------------------------
    def _pick(self):
        f, _ = QFileDialog.getOpenFileName(self, "Escolha um arquivo", "", "Todos (*.*)")
        if f:
            self.file_line.setText(f); self.status.showMessage("Arquivo selecionado.")

    def _start(self, encrypt: bool):
        path, pwd = self.file_line.text(), self.pwd.text()
        if not path: return self.status.showMessage("Selecione um arquivo.")
        if not pwd : return self.status.showMessage("Digite a senha.")

        # Ensure password is bytes
        if isinstance(pwd, str):
            pwd = pwd.encode('utf-8')

        size = Path(path).stat().st_size
        profile = list(SecurityProfile)[self.cmb_prof.currentIndex()]
        algo_idx = self.cmb_alg.currentIndex()
        stream   = (algo_idx == 1 and size >= STREAMING_THRESHOLD)

        # Calculate correct total bytes for progress bar
        if encrypt:
            self._total_bytes = size  # Original file size
        else:
            # Read plaintext size from .meta file
            try:
                meta_file = PathLib(path + ".meta")
                if meta_file.exists():
                    meta_data = loads(meta_file.read_bytes()[16+12:])
                    self._total_bytes = meta_data["size"]
                else:
                    self._total_bytes = size  # Fallback to encrypted file size
            except:
                self._total_bytes = size  # Fallback to encrypted file size

        if encrypt:
            func = encrypt_aes if algo_idx == 0 else (encrypt_chacha_stream if stream else encrypt_chacha)
        else:
            func = decrypt_aes if algo_idx == 0 else (decrypt_chacha_stream if stream else decrypt_chacha)

        # prepara UI
        self._toggle(False)
        self.prg.setValue(0); self.lbl_time.setText("Tempo: – s")

        # inicia worker
        self.worker = CryptoWorker(func, path, pwd, profile)
        self.worker.progress.connect(self._progress)
        self.worker.finished.connect(self._finished)
        self.worker.error   .connect(self._error)
        self.worker.start(); self.pwd.clear()

    # ----- slots -------------------------------------------------------------------
    def _progress(self, done:int, elapsed:float):
        pct = int(done * 100 / self._total_bytes) if self._total_bytes else 0
        pct = min(pct, 100)  # Ensure it doesn't exceed 100%
        self.prg.setValue(pct)
        self.lbl_time.setText(f"Tempo: {elapsed:,.1f} s")

    def _finished(self, out_path:str):
        self.prg.setValue(100)                    # <-- força 100 %
        QMessageBox.information(self, "Sucesso", f"Arquivo gerado:\n{out_path}")
        self.status.showMessage("✔️ Concluído!", 8000)
        self._toggle(True)

    def _error(self, msg:str):
        QMessageBox.critical(self, "Erro", msg)
        self.status.showMessage(f"Erro: {msg}", 12000)
        self._toggle(True)

    def _toggle(self, enabled:bool):
        for w in (self.btn_enc, self.btn_dec, self.cmb_alg, self.cmb_prof):
            w.setEnabled(enabled)

    # ----- dark theme --------------------------------------------------------------
    def _apply_dark_palette(self):
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor("#263238"))
        palette.setColor(QPalette.Base,   QColor("#37474F"))
        palette.setColor(QPalette.Text,   QColor("#ECEFF1"))
        palette.setColor(QPalette.Button, QColor("#37474F"))
        palette.setColor(QPalette.ButtonText, QColor("#ECEFF1"))
        palette.setColor(QPalette.Highlight, QColor("#29B6F6"))
        palette.setColor(QPalette.HighlightedText, QColor("#FFFFFF"))
        QApplication.setPalette(palette)

# ─────────── main ────────────────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    
    # Ensure log file exists and has initial content
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_PATH.touch(exist_ok=True)
    
    # Initialize logger with first entry
    from crypto_core.logger import logger
    logger.info("=== CryptGuard iniciado ===")
    
    window = MainWindow(); window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    from crypto_core import _cli   # noqa: triggers argument parsing (handled)
    main()
