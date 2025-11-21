#!/usr/bin/env python3
"""
CryptGuardv2 - secure GUI (v5 SecretStream)
Interface clássica com painel KeyGuard (Qt) e pipeline único de criptografia (v5).
"""

from __future__ import annotations

# --- Anti-shadow da stdlib 'platform' ---
import platform as _stdlib_platform, os

_std = getattr(_stdlib_platform, "__file__", "") or ""
if not _std.endswith("platform.py"):
    print(
        "Erro: pacote local chamado 'platform' está sombreamento a stdlib. "
        "Renomeie para 'cg_platform'."
    )
    os._exit(1)
# --- fim anti-shadow ---

# --- Bootstrap Qt (Linux): preferir Wayland, cair para XCB ---
import sys

if sys.platform.startswith("linux"):
    if "QT_QPA_PLATFORM" not in os.environ:
        if os.environ.get("XDG_SESSION_TYPE", "").lower() == "wayland" or os.environ.get(
            "WAYLAND_DISPLAY"
        ):
            os.environ["QT_QPA_PLATFORM"] = "wayland;xcb"
        else:
            os.environ["QT_QPA_PLATFORM"] = "xcb"
# --- fim bootstrap ---

# --------------------------------------------------------------- Standard library ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------â"€â"€
import contextlib
import importlib.util
import inspect
import json
import locale
import pathlib
import shutil
import subprocess
import time
import warnings
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cg_platform import IS_LINUX, IS_WIN
from cg_platform.fs_paths import APP_NAME as PLATFORM_APP_NAME, ORG_NAME as PLATFORM_ORG_NAME
from cg_platform.linux_env import (
    explain_qpa_failure,
    harden_process_best_effort as harden_process_best_effort_linux,
)
from cg_platform.win_effects import try_enable_dark_titlebar, try_enable_mica
from crypto_core.verify_integrity import verify_integrity
# --------------------------------------------------------------- PySide6 / Qt ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
import nacl
from nacl import bindings as nb
from nacl.bindings import crypto_secretstream_xchacha20poly1305_state
from PySide6.QtCore import (
    QCoreApplication,
    QDate,
    QLocale,
    QSize,
    QThread,
    QTimer,
    QTranslator,
    QUrl,
    Signal,
)
from PySide6.QtGui import (
    QColor,
    QDesktopServices,
    QDragEnterEvent,
    QDropEvent,
    QPalette,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QStatusBar,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

import qtawesome as qta

from crypto_core.factories import decrypt as cg_decrypt

# --------------------------------------------------------------- Imports do Projeto ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
from crypto_core.factories import encrypt as cg_encrypt
from crypto_core.secure_bytes import SecureBytes

# Imports do Vault com fallback apropriado
try:
    from vault import (
        AtomicStorageBackend,
        Config,
        CorruptVault,
        VaultDialog,
        VaultLocked,
        VaultManager,
        WrongPassword,
        open_or_init_vault,
        password_whitespace_hint,
    )

    USING_V2 = True
except ImportError:
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
        VaultDialog,
        VaultManager,
        WrongPassword,
        open_or_init_vault,
        password_whitespace_hint,
    )

    USING_V2 = False

    # Define VaultLocked se não existir
    if "VaultLocked" not in locals():

        class VaultLocked(Exception):
            pass


from crypto_core import LOG_PATH
from crypto_core.config import HYGIENE_DEFAULT_SETTINGS, SETTINGS_PATH
from crypto_core.file_hygiene import TempFolderManager, cleanup_temp_folder, is_ssd, secure_delete_file
from crypto_core.fileformat_v5 import read_header_version_any
from crypto_core.logger import logger
from crypto_core.securemem import ensure_securemem_ready
from crypto_core.utils import archive_folder, secure_delete

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
except Exception as exc:
    logger.debug("locale.setlocale fallback: %s", exc)

STRICT_SECUREMEM = os.getenv("CG_SECUREMEM_STRICT", "0") == "1"
ensure_securemem_ready(strict=STRICT_SECUREMEM)

if sys.platform.startswith("linux") and os.getenv("CG_HARDEN_LINUX", "1") == "1":
    try:
        from crypto_core.hardening_linux import harden_process_best_effort

        harden_process_best_effort(logger=logger)
    except Exception:
        pass

# --- NEW: KeyGuard sidebar (Qt) ---
# Carrega o helper com fallback robusto caso o pacote não esteja em modules/keyguard/.
attach_keyguard_qt = None
try:
    from modules.keyguard import attach_keyguard_qt  # caminho preferido
except Exception:
    attach_keyguard_qt = None
    try:
        import importlib.util
        import pathlib

        _BASE = pathlib.Path(__file__).resolve().parent
        for _cand in (
            _BASE / "modules" / "keyguard" / "qt_pane.py",
            _BASE / "qt_pane.py",
        ):
            if _cand.exists():
                _spec = importlib.util.spec_from_file_location("keyguard_qt_pane", _cand)
                _mod = importlib.util.module_from_spec(_spec)  # type: ignore
                if not _spec or not _spec.loader:
                    raise RuntimeError("KeyGuard Qt pane loader indispon?vel")
                _spec.loader.exec_module(_mod)  # type: ignore
                attach_keyguard_qt = getattr(_mod, "attach_keyguard_qt", None)
                if attach_keyguard_qt:
                    break
    except Exception as exc:
        logger.debug("KeyGuard Qt dynamic import fallback falhou: %s", exc)
        attach_keyguard_qt = None

# (removido) Detecção de algoritmos legados — o app escreve apenas v5 SecretStream

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


# (removidas) classes antigas não utilizadas: AccentButton, GradientHeader

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
        operation: str,  # 'encrypt', 'decrypt' ou 'verify'
        src_path: str,
        password: str,
        delete_flag: bool = False,
        extra_params: dict | None = None,
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
        self._password_secure = SecureBytes(
            password.encode() if isinstance(password, str) else password
        )

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
            logger.debug("CryptoWorker interrupted during %s", self.operation)
        except Exception as e:
            logger.exception("CryptoWorker error during %s: %s", self.operation, e)
            self.error.emit(str(e))
        finally:
            # Clear password from memory deterministically
            if hasattr(self, "_password_secure") and self._password_secure is not None:
                with contextlib.suppress(Exception):
                    self._password_secure.clear()

    def _resolve_keyfile(self) -> str | None:
        """Return a validated keyfile path or None."""
        keyfile = self.extra_params.get("keyfile")
        if not keyfile:
            return None
        key_path = Path(keyfile)
        if not key_path.exists():
            raise FileNotFoundError(f"Keyfile not found: {key_path}")
        return str(key_path)

    def _encrypt(self, progress_cb: Callable, password_secure: SecureBytes) -> Path:
        """Executa criptografia."""
        src = Path(self.src_path)
        out_path = self.extra_params.get("out_path", src.with_suffix(".cg2"))
        # Route via v5 factories; fixed algorithm, pass kdf profile and padding

        result_path: str | None = None

        try:
            keyfile_path = self._resolve_keyfile()
            if hasattr(password_secure, "with_bytes"):

                def _run_encrypt(pwd: bytes) -> None:
                    nonlocal result_path
                    result_path = cg_encrypt(
                        in_path=str(src),
                        out_path=str(out_path),
                        password=pwd,
                        algo="SecretStream",  # ignorado mas necessário para compatibilidade
                        progress_cb=progress_cb,
                        kdf_profile=self.extra_params.get("kdf_profile", "INTERACTIVE"),
                        pad_block=self.extra_params.get("pad_block", 0),
                        keyfile=keyfile_path,
                        hide_filename=self.extra_params.get("hide_filename", False),
                        expires_at=self.extra_params.get("exp_ts"),
                    )

                password_secure.with_bytes(_run_encrypt)
            else:
                mv = password_secure.view()
                try:
                    result_path = cg_encrypt(
                        in_path=str(src),
                        out_path=str(out_path),
                        password=bytes(mv),
                        algo="SecretStream",
                        progress_cb=progress_cb,
                        kdf_profile=self.extra_params.get("kdf_profile", "INTERACTIVE"),
                        pad_block=self.extra_params.get("pad_block", 0),
                        keyfile=keyfile_path,
                        hide_filename=self.extra_params.get("hide_filename", False),
                        expires_at=self.extra_params.get("exp_ts"),
                    )
                finally:
                    with contextlib.suppress(Exception):
                        mv.release()

            if result_path is None:
                raise RuntimeError("Encryption did not produce an output path")
            return Path(result_path)
        except TypeError as e:
            # Erro comum quando a instalação do PyNaCl/libsodium está quebrada ou
            # houve mudança de assinatura inesperada.
            msg = str(e)
            if (
                "crypto_secretstream_xchacha20poly1305_init_push" in msg
                and "missing 1 required positional argument" in msg
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

        result_path: str | None = None

        keyfile_path = self._resolve_keyfile()
        verify_only = bool(self.extra_params.get("verify_only", False))

        if hasattr(password_secure, "with_bytes"):

            def _run_decrypt(pwd: bytes) -> None:
                nonlocal result_path
                result_path = cg_decrypt(
                    in_path=str(src),
                    out_path=str(out_path),
                    password=pwd,
                    verify_only=verify_only,
                    progress_cb=progress_cb,
                    keyfile=keyfile_path,
                )

            password_secure.with_bytes(_run_decrypt)
        else:
            mv = password_secure.view()
            try:
                result_path = cg_decrypt(
                    in_path=str(src),
                    out_path=str(out_path),
                    password=bytes(mv),
                    verify_only=verify_only,
                    progress_cb=progress_cb,
                    keyfile=keyfile_path,
                )
            finally:
                with contextlib.suppress(Exception):
                    mv.release()

        return Path(result_path) if result_path else Path("")

    def cancel(self):
        """Cancela operação."""
        self._cancelled = True
        self.requestInterruption()


# ------------------------------------------------------------------------------------------------------------------------------──
#                            SETTINGS DIALOG
# ------------------------------------------------------------------------------------------------------------------------------──


class SettingsDialog(QDialog):
    """Dialog for application settings with tabbed interface."""
    
    def __init__(self, parent: QWidget | None, settings: dict):
        super().__init__(parent)
        self.setWindowTitle("CryptGuard Settings")
        self.setMinimumSize(600, 500)
        
        # Store original settings
        self.input_settings = settings.copy()
        self.result_settings = settings.copy()
        
        # Create UI
        self._build_ui()
        
        # Load current settings into controls
        self._load_settings_to_ui()
    
    def _build_ui(self):
        """Build the settings dialog UI with tabs."""
        layout = QVBoxLayout(self)
        
        # Tab widget
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Create tabs
        self._create_general_tab()
        self._create_hygiene_tab()
        
        # Dialog buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
    
    def _create_general_tab(self):
        """Create general settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Clipboard auto-clear
        group_clipboard = QGroupBox("Clipboard")
        group_layout = QVBoxLayout(group_clipboard)
        
        self.chk_clipboard_autoclear = QCheckBox("Auto-clear clipboard after 30 seconds")
        self.chk_clipboard_autoclear.setToolTip(
            "Automatically clear the clipboard 30 seconds after copying a password"
        )
        group_layout.addWidget(self.chk_clipboard_autoclear)
        
        layout.addWidget(group_clipboard)
        
        # Fixed output directory
        group_output = QGroupBox("Output Directory")
        group_layout2 = QVBoxLayout(group_output)
        
        self.chk_fixed_out = QCheckBox("Use fixed output directory")
        self.chk_fixed_out.toggled.connect(self._toggle_fixed_out)
        group_layout2.addWidget(self.chk_fixed_out)
        
        dir_layout = QHBoxLayout()
        self.ed_fixed_dir = QLineEdit()
        self.ed_fixed_dir.setPlaceholderText("Select output directory...")
        dir_layout.addWidget(self.ed_fixed_dir)
        
        self.btn_browse_dir = QPushButton("Browse...")
        self.btn_browse_dir.clicked.connect(self._browse_output_dir)
        dir_layout.addWidget(self.btn_browse_dir)

        group_layout2.addLayout(dir_layout)
        layout.addWidget(group_output)

        # Security tools: keyfile generation and secure containers
        group_security = QGroupBox("Security Tools")
        sec_layout = QVBoxLayout(group_security)

        btn_gen_keyfile = QPushButton("Generate secure keyfile (64 bytes)")
        btn_gen_keyfile.clicked.connect(self._generate_keyfile)
        sec_layout.addWidget(btn_gen_keyfile)

        containers_row = QHBoxLayout()
        btn_create_container = QPushButton("Create Secure Container")
        btn_create_container.clicked.connect(self._create_container)
        containers_row.addWidget(btn_create_container)

        btn_read_container = QPushButton("Open Secure Container")
        btn_read_container.clicked.connect(self._read_container)
        containers_row.addWidget(btn_read_container)
        containers_row.addStretch()
        sec_layout.addLayout(containers_row)

        layout.addWidget(group_security)

        # Spacer
        layout.addStretch()

        self.tabs.addTab(tab, "General")
    
    def _create_hygiene_tab(self):
        """Create file hygiene settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # SSD Warning at top
        warning_frame = QFrame()
        warning_frame.setFrameShape(QFrame.StyledPanel)
        warning_frame.setStyleSheet(
            "QFrame { background-color: rgba(255, 152, 0, 0.1); "
            "border: 1px solid rgba(255, 152, 0, 0.3); "
            "border-radius: 4px; padding: 8px; }"
        )
        warning_layout = QVBoxLayout(warning_frame)
        
        warning_label = QLabel(
            "⚠️  <b>Important:</b> Secure deletion is NOT fully effective on SSDs/NVMe drives "
            "due to wear leveling.<br>"
            "For maximum security, use full-disk encryption (BitLocker, LUKS, FileVault)."
        )
        warning_label.setWordWrap(True)
        warning_layout.addWidget(warning_label)
        
        layout.addWidget(warning_frame)
        
        # Auto-delete original
        group_delete = QGroupBox("Automatic Deletion")
        group_layout = QVBoxLayout(group_delete)
        
        self.chk_delete_original = QCheckBox("Delete original file after encryption")
        self.chk_delete_original.setToolTip(
            "Automatically delete the original file after successful encryption.\n"
            "Uses secure deletion with multiple overwrite passes."
        )
        group_layout.addWidget(self.chk_delete_original)
        
        passes_layout = QHBoxLayout()
        passes_label = QLabel("Secure deletion passes:")
        passes_layout.addWidget(passes_label)
        
        self.spin_passes = QSpinBox()
        self.spin_passes.setRange(1, 7)
        self.spin_passes.setValue(3)
        self.spin_passes.setToolTip(
            "Number of overwrite passes (1-7).\n"
            "More passes = slower but more thorough.\n"
            "3 passes is a good balance."
        )
        passes_layout.addWidget(self.spin_passes)
        passes_layout.addStretch()
        
        group_layout.addLayout(passes_layout)
        
        layout.addWidget(group_delete)
        
        # Temporary files
        group_temp = QGroupBox("Temporary Files")
        group_layout2 = QVBoxLayout(group_temp)
        
        self.chk_clean_startup = QCheckBox("Clean temporary files on startup")
        self.chk_clean_startup.setToolTip(
            "Automatically remove temporary files older than 24 hours when the application starts"
        )
        group_layout2.addWidget(self.chk_clean_startup)
        
        self.chk_clean_shutdown = QCheckBox("Clean temporary files on shutdown")
        self.chk_clean_shutdown.setToolTip(
            "Automatically remove temporary files older than 1 hour when the application exits"
        )
        group_layout2.addWidget(self.chk_clean_shutdown)
        
        # Clean Now button
        cleanup_layout = QHBoxLayout()
        cleanup_layout.addStretch()
        
        self.btn_clean_now = QPushButton("Clean Temporary Files Now")
        self.btn_clean_now.setIcon(qta.icon("fa5s.broom", color="#536dfe"))
        self.btn_clean_now.clicked.connect(self._clean_now)
        self.btn_clean_now.setStyleSheet(
            "QPushButton { padding: 8px 16px; font-weight: bold; }"
        )
        cleanup_layout.addWidget(self.btn_clean_now)
        
        group_layout2.addLayout(cleanup_layout)
        
        layout.addWidget(group_temp)
        
        # Spacer
        layout.addStretch()
        
        self.tabs.addTab(tab, "File Hygiene")
    
    def _toggle_fixed_out(self, checked: bool):
        """Enable/disable fixed output directory controls."""
        self.ed_fixed_dir.setEnabled(checked)
        self.btn_browse_dir.setEnabled(checked)
    
    def _browse_output_dir(self):
        """Browse for output directory."""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory",
            self.ed_fixed_dir.text() or str(Path.home())
        )
        if dir_path:
            self.ed_fixed_dir.setText(dir_path)
    
    def _clean_now(self):
        """Trigger manual cleanup."""
        try:
            manager = TempFolderManager()
            manager.ensure_dirs()
            stats = manager.get_temp_stats()
            
            if stats["file_count"] == 0:
                QMessageBox.information(
                    self,
                    "Temp Cleanup",
                    "No temporary files to clean."
                )
                return
            
            size_mb = stats["total_bytes"] / (1024 * 1024)
            msg = (
                f"Found {stats['file_count']} temporary file(s) "
                f"using {size_mb:.2f} MB.\n\n"
                f"Do you want to delete these files?"
            )
            
            reply = QMessageBox.question(
                self,
                "Clean Temporary Files",
                msg,
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply != QMessageBox.Yes:
                return
            
            # Perform cleanup
            files_removed, bytes_freed = cleanup_temp_folder(max_age_hours=0, dry_run=False)
            size_freed_mb = bytes_freed / (1024 * 1024)
            
            QMessageBox.information(
                self,
                "Cleanup Complete",
                f"Removed {files_removed} file(s), freed {size_freed_mb:.2f} MB"
            )
            
        except Exception as exc:
            logger.exception("Manual temp cleanup failed")
            QMessageBox.warning(
                self,
                "Cleanup Error",
                f"Failed to clean temporary files:\n{exc}"
            )
    
    def _load_settings_to_ui(self):
        """Load current settings into UI controls."""
        # General tab
        self.chk_clipboard_autoclear.setChecked(
            self.input_settings.get("clipboard_autoclear", True)
        )
        self.chk_fixed_out.setChecked(
            self.input_settings.get("fixed_out_enabled", False)
        )
        self.ed_fixed_dir.setText(
            self.input_settings.get("fixed_out_dir", "")
        )
        self._toggle_fixed_out(self.chk_fixed_out.isChecked())
        
        # Hygiene tab
        self.chk_delete_original.setChecked(
            self.input_settings.get("hygiene_delete_original", False)
        )
        self.chk_clean_startup.setChecked(
            self.input_settings.get("hygiene_clean_startup", True)
        )
        self.chk_clean_shutdown.setChecked(
            self.input_settings.get("hygiene_clean_shutdown", True)
        )
        self.spin_passes.setValue(
            self.input_settings.get("hygiene_passes", 3)
        )
    
    def _on_accept(self):
        """Save settings and close."""
        # General settings
        self.result_settings["clipboard_autoclear"] = self.chk_clipboard_autoclear.isChecked()
        self.result_settings["fixed_out_enabled"] = self.chk_fixed_out.isChecked()
        self.result_settings["fixed_out_dir"] = self.ed_fixed_dir.text()
        
        # Hygiene settings
        self.result_settings["hygiene_delete_original"] = self.chk_delete_original.isChecked()
        self.result_settings["hygiene_clean_startup"] = self.chk_clean_startup.isChecked()
        self.result_settings["hygiene_clean_shutdown"] = self.chk_clean_shutdown.isChecked()
        self.result_settings["hygiene_passes"] = self.spin_passes.value()

        self.accept()

    def _generate_keyfile(self):
        """Generate a 64-byte keyfile and select it in the main window."""
        try:
            key_data = os.urandom(64)
            default_name = "cryptguard.keyfile"
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Secure Keyfile",
                default_name,
                "Keyfiles (*.keyfile *.key);;All Files (*)",
            )
            if not file_path:
                return
            Path(file_path).write_bytes(key_data)
            QMessageBox.information(
                self,
                "Success",
                f"Secure keyfile (64 bytes) saved successfully to:\n{file_path}",
            )
            main_window = self.parent()
            if main_window and hasattr(main_window, "keyfile_input") and hasattr(main_window, "check_keyfile"):
                main_window.keyfile_input.setText(file_path)
                main_window.check_keyfile.setChecked(True)
                if hasattr(main_window, "status_bar"):
                    main_window.status_bar.showMessage("New keyfile generated and selected.", 5000)
        except Exception as exc:
            logger.error("Failed to generate keyfile", exc_info=exc)
            QMessageBox.warning(self, "Error", f"Could not generate keyfile:\n{exc}")

    def _create_container(self):
        """Abre o wizard de criação de container."""
        try:
            from ui.settings_containers import ContainerCreateDialog

            main_window = self.parent()
            if not main_window:
                QMessageBox.warning(
                    self,
                    "Erro",
                    "Não foi possível acessar a janela principal.",
                )
                return

            cg_items = []
            cg_vault_dir = None

            if hasattr(main_window, "vm") and main_window.vm and main_window.vm._opened:
                vm = main_window.vm
                cg_vault_dir = vm.path.parent

                for file_id in vm.order:
                    if file_id in vm.entries:
                        entry = vm.entries[file_id]
                        created_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(entry.created))
                        cg_items.append(
                            {
                                "id": file_id,
                                "path": file_id,
                                "name": entry.label,
                                "size": len(entry.data),
                                "extension": ".cg2",
                                "orig_name": entry.label,
                                "data": entry.data,
                                "created_at": created_iso,
                                "modified_at": created_iso,
                            }
                        )
            else:
                reply = QMessageBox.question(
                    self,
                    "CryptGuard Vault Fechado",
                    "O CryptGuard Vault não está aberto.\n\n"
                    "Deseja continuar sem adicionar arquivos do CryptGuard?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if reply != QMessageBox.StandardButton.Yes:
                    return

                cg_vault_dir = Path.home() / "CryptGuard" / "vault"

            kg_entries = []

            if hasattr(main_window, "keyguard_pane") and main_window.keyguard_pane:
                kg_pane = main_window.keyguard_pane
                if hasattr(kg_pane, "_vault_mgr") and kg_pane._vault_mgr and kg_pane._vault_mgr._opened:
                    kg_vm = kg_pane._vault_mgr

                    for entry in kg_vm.entries.values():
                        kg_entries.append(
                            {
                                "name": entry.name,
                                "password_b64": entry.password_b64,
                                "metadata": entry.metadata,
                                "id": entry.name,
                                "created": entry.created,
                                "modified": entry.modified,
                            }
                        )

            if not cg_items and not kg_entries:
                QMessageBox.information(
                    self,
                    "Vaults Vazios",
                    "Nenhum vault está aberto ou não há itens disponíveis.\n\n"
                    "Para criar um container:\n"
                    "1. Abra o CryptGuard Vault e/ou KeyGuard Vault\n"
                    "2. Adicione alguns arquivos ou senhas\n"
                    "3. Tente novamente",
                )
                return

            if cg_vault_dir is None:
                cg_vault_dir = Path.home() / "CryptGuard" / "vault"

            dialog = ContainerCreateDialog(cg_items, kg_entries, cg_vault_dir, self)
            dialog.exec()

        except ImportError as exc:
            logger.error("Módulo de containers não disponível: %s", exc)
            QMessageBox.warning(
                self,
                "Recurso Não Disponível",
                "O módulo de Secure Containers não está disponível.\n"
                "Verifique a instalação.",
            )
        except Exception as exc:
            logger.error("Erro ao abrir dialog de criação de container: %s", exc, exc_info=True)
            QMessageBox.critical(
                self,
                "Erro",
                f"Não foi possível abrir o assistente de criação:\n{exc}",
            )

    def _read_container(self):
        """Abre dialog para ler container existente."""
        try:
            from ui.settings_containers import ContainerReadDialog

            main_window = self.parent()
            if not main_window:
                QMessageBox.warning(
                    self,
                    "Erro",
                    "Não foi possível acessar a janela principal.",
                )
                return

            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Abrir Secure Container",
                str(Path.home()),
                "Vault Files (*.vault *.cgsc);;All Files (*)",
            )

            if not file_path:
                return

            container_path = Path(file_path)

            password, ok = QInputDialog.getText(
                self,
                "Senha do Container",
                "Digite a senha do container:",
                QLineEdit.EchoMode.Password,
            )

            if not ok or not password:
                return

            dialog = ContainerReadDialog(
                container_path,
                password.encode("utf-8"),
                parent=self,
                main_window=main_window,
            )
            dialog.exec()

        except ImportError as exc:
            logger.error("Módulo de containers não disponível: %s", exc)
            QMessageBox.warning(
                self,
                "Recurso Não Disponível",
                "O módulo de Secure Containers não está disponível.\n"
                "Verifique a instalação.",
            )
        except Exception as exc:
            logger.error("Erro ao abrir dialog de leitura de container: %s", exc, exc_info=True)
            QMessageBox.critical(
                self,
                "Erro",
                f"Não foi possível abrir o container:\n{exc}",
            )


# ------------------------------------------------------------------------------------------------------------------------------â•â•
#                        MAIN WINDOW (Interface Antiga)
# ------------------------------------------------------------------------------------------------------------------------------â•â•


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptGuardv2 - secure")
        # Ajuste de tamanho da janela para 1920×1080 @125%
        self.setMinimumSize(QSize(1100, 700))
        self.resize(QSize(1100, 700))
        # leve transparência global para efeito "glass"
        self.setWindowOpacity(0.96)

        # Aplica paleta antiga PRIMEIRO
        self._apply_palette_old_theme()

        # Estado
        self.vm: VaultManager | None = None
        self.worker: CryptoWorker | None = None
        self._temp_files: list[Path] = []
        self._original_path = ""
        self._tmp_zip = None
        self._settings = self._load_settings()
        self._clipboard_token: str | None = None
        self._forced_out = ""
        self._is_encrypt = False
        self._is_verify = False
        self._cancel_timer = None
        # Simple rate limiting (per file path)
        self._failed_attempts = {}
        self._lockout_until = {}

        # Constrói UI
        self._build_ui()

        # Garantir KeyGuard apos montar a UI (próximo ciclo do event loop)
        QTimer.singleShot(0, self._ensure_keyguard)
        self.setAcceptDrops(True)
        
        # Higiene: cleanup de temporários na inicialização (se habilitado)
        if self._settings.get("hygiene_clean_startup", True):
            QTimer.singleShot(100, self._cleanup_temp_on_startup)

    # ----------------------------- tema/paleta (faltante) -----------------------------
    def _apply_palette_old_theme(self) -> None:
        """
        Define paleta dark + CSS base (atualizado para transparência e botões modernos).
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
            QWidget {
                /* Fundo base transparente para efeito glassmorphism */
                background: transparent;
                color: #e6eaf0;
            }

            MainWindow, QFrame {
                background-color: rgba(27, 33, 43, 0.9);
            }

            QLabel {
                background-color: transparent;
                color: #e6eaf0;
            }

            QLineEdit, QPlainTextEdit, QTextEdit, QComboBox, QDateEdit, QSpinBox {
                background: rgba(42, 51, 66, 0.8);
                color: #e6eaf0;
                border: 1px solid #3a4356;
                border-radius: 6px;
                padding: 6px;
            }

            QLineEdit:focus,
            QPlainTextEdit:focus,
            QTextEdit:focus,
            QComboBox:focus,
            QDateEdit:focus,
            QSpinBox:focus {
                border-color: #536dfe;
            }

            QComboBox QAbstractItemView {
                background: #2a3342;
                color: #e6eaf0;
                selection-background-color: #536dfe;
            }

            /* Dialog windows share glass theme */
            QDialog, QMessageBox, QInputDialog {
                background-color: rgba(27, 33, 43, 0.95);
                border: 1px solid #3a4356;
                color: #e6eaf0;
            }

            QDialog QLabel, QMessageBox QLabel, QInputDialog QLabel {
                background: transparent;
                color: #e6eaf0;
            }

            QDialog QLineEdit, QInputDialog QLineEdit {
                background: rgba(42, 51, 66, 0.8);
                color: #e6eaf0;
                border: 1px solid #3a4356;
                border-radius: 6px;
                padding: 6px;
            }

            QDialog QLineEdit:focus, QInputDialog QLineEdit:focus {
                border-color: #536dfe;
            }

            QDialogButtonBox {
                background: transparent;
            }

            QDialogButtonBox QPushButton,
            QDialog QPushButton,
            QMessageBox QPushButton {
                background: #303a4b;
                color: #e6eaf0;
                border: none;
                border-radius: 6px;
                padding: 6px 16px;
                min-width: 80px;
            }

            QDialogButtonBox QPushButton:hover,
            QDialog QPushButton:hover,
            QMessageBox QPushButton:hover {
                background: #4a5568;
            }

            QDialogButtonBox QPushButton:default,
            QDialog QPushButton:default,
            QMessageBox QPushButton:default {
                background-color: #536dfe;
                color: #ffffff;
            }

            QDialogButtonBox QPushButton:default:hover,
            QDialog QPushButton:default:hover,
            QMessageBox QPushButton:default:hover {
                background-color: #6b7fff;
            }

            QDialog QGroupBox {
                background-color: rgba(42, 51, 66, 0.7);
                border: 1px solid #3a4356;
                border-radius: 6px;
                margin-top: 10px;
                padding: 10px;
                padding-top: 15px;
            }

            QDialog QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
                margin-left: 10px;
                background-color: rgba(27, 33, 43, 0.95);
                color: #e6eaf0;
            }

            /* Botões principais (Encrypt/Decrypt/Verify) */
            QPushButton#mainActionButton {
                background: transparent;
                color: #e6eaf0;
                border: 1px solid #4a5568;
                border-radius: 8px;
                padding: 10px;
                font-weight: bold;
                font-size: 11pt;
            }

            QPushButton#mainActionButton:hover {
                background: rgba(74, 85, 104, 0.5);
                border-color: #5a6578;
            }

            QPushButton#mainActionButton:pressed {
                background: rgba(74, 85, 104, 0.8);
            }

            /* Botão cancel em destaque */
            QPushButton#cancelButton {
                background: #4e586e;
                color: #e6eaf0;
                border: none;
                border-radius: 8px;
                padding: 10px;
                font-weight: bold;
                font-size: 11pt;
            }

            QPushButton#cancelButton:hover {
                background: #5a6578;
            }

            /* Botões de rodapé (flat) */
            QPushButton#footerButton {
                background: transparent;
                color: #9aa3b2;
                border: none;
                border-radius: 6px;
                padding: 5px;
                font-weight: normal;
                text-align: left;
            }

            QPushButton#footerButton:hover {
                background: rgba(74, 85, 104, 0.3);
                color: #e6eaf0;
            }

            /* Botões padrão */
            QPushButton {
                background: #303a4b;
                color: #e6eaf0;
                border: none;
                border-radius: 6px;
                padding: 6px 12px;
            }

            QPushButton:hover {
                background: #4a5568;
            }

            QPushButton:pressed {
                background: #364152;
            }

            QPushButton:disabled {
                background: #2a3443;
                color: #6d7689;
            }

            QCheckBox {
                padding: 0px 2px;
                margin: 0;
                color: #e6eaf0;
            }

            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                background-color: #2a3342;
                border: 2px solid #3a4356;
                border-radius: 3px;
            }

            QCheckBox::indicator:hover {
                border-color: #536dfe;
            }

            QCheckBox::indicator:checked {
                background-color: #536dfe;
                border-color: #536dfe;
                image: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTYiIGhlaWdodD0iMTYiIHZpZXdCb3g9IjAgMCAxNiAxNiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTEzLjUgNC41TDYgMTJMMi41IDguNSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSIyIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz4KPC9zdmc+);
            }

            QCheckBox::indicator:checked:hover {
                background-color: #6b7fff;
                border-color: #6b7fff;
            }

            QCheckBox::indicator:disabled {
                background-color: #1f2633;
                border-color: #2a3342;
            }

            QProgressBar {
                background: rgba(31, 38, 51, 0.8);
                color: #e6eaf0;
                height: 12px;
                border: 1px solid #3a4356;
                border-radius: 4px;
                text-align: center;
            }

            QProgressBar::chunk {
                background: #536dfe;
            }

            QStatusBar {
                background: rgba(21, 26, 34, 0.85);
                color: #9aa3b2;
            }

            QToolTip {
                background: rgba(43, 51, 66, 0.95);
                color: #e6eaf0;
                border: 1px solid #3a4356;
            }
        """)

    # --- KeyGuard integration (centralizado) ------------------------------
    def _ensure_keyguard(self) -> None:
        """Anexa o KeyGuard (Qt) no lado direito (com fallback de import) uma única vez."""
        # Se ainda não temos helper, tenta novamente o fallback dinâmico.
        helper = getattr(self, "_attach_keyguard_qt", attach_keyguard_qt)
        if helper is None:
            try:
                _BASE = pathlib.Path(__file__).resolve().parent
                for _cand in (
                    _BASE / "modules" / "keyguard" / "qt_pane.py",
                    _BASE / "qt_pane.py",
                ):
                    if _cand.exists():
                        _spec = importlib.util.spec_from_file_location("keyguard_qt_pane", _cand)
                        _mod = importlib.util.module_from_spec(_spec)  # type: ignore
                        assert _spec and _spec.loader
                        _spec.loader.exec_module(_mod)  # type: ignore
                        helper = getattr(_mod, "attach_keyguard_qt", None)
                        if helper:
                            self._attach_keyguard_qt = helper
                            break
            except Exception as e:
                logger.exception("Falha ao importar KeyGuard: %s", e)
                helper = None
        if helper is None:
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
            pane = helper(self, width=380)
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
            # Também envia para o clipboard e agenda limpeza se configurado
            self._copy_password_to_clipboard_and_maybe_clear(pwd)
        except Exception as exc:
            logger.exception("Failed to apply generated password", exc_info=exc)

    # (removidos) helpers antigos não utilizados: _field, _combo

    # ───────────────────────────── Clipboard helpers ─────────────────────────────
    def _copy_password_to_clipboard_and_maybe_clear(self, pwd: str) -> None:
        """Copia a senha para o clipboard e, se habilitado, agenda limpeza em 30s."""
        try:
            cb = QApplication.clipboard()
            cb.setText(pwd)
            # guarda token para não apagar se o usuário colar outra coisa
            self._clipboard_token = pwd
            if bool(self._settings.get("clipboard_autoclear", False)):
                QTimer.singleShot(30_000, self._clear_clipboard_if_unchanged)
        except Exception as exc:
            logger.exception("Clipboard update failed", exc_info=exc)

    def _clear_clipboard_if_unchanged(self) -> None:
        try:
            cb = QApplication.clipboard()
            # só limpa se ainda for a mesma senha
            if self._clipboard_token and cb.text() == self._clipboard_token:
                cb.clear()
        finally:
            self._clipboard_token = None

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
        self.strength_bar.setStyleSheet(
            f"QProgressBar::chunk{{background:{colors[min(score, 4)]};}}"
        )

    # ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------â"€
    #                           EVENT HANDLERS
    # ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------â"€

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
                try:
                    ver = read_header_version_any(path)
                    file_type = "CG2 v5" if ver >= 5 else "CG2 (legacy)"
                except Exception:
                    file_type = "file"
                self.status_bar.showMessage(f"{file_type} loaded via drag & drop: {path.name}")

    def _detect_algo(self, path: str):
        """Detect CG2 version (v1–v4 legacy or v5) and update status."""
        try:
            src = Path(path)
            if not src.exists() or src.is_dir():
                return
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

    # ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------â"€
    #                               SLOTS
    # ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------â"€

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
        except Exception as exc:
            logger.debug("Failed to update password visibility label: %s", exc)

    def _guard_password_whitespace(self, pwd: str, parent_title: str) -> bool:
        hint = password_whitespace_hint(pwd)
        if hint is None:
            return True
        QMessageBox.warning(
            self,
            parent_title,
            f"{hint}\nRemova os espaços em branco e tente novamente.",
        )
        return False

    def _start_operation(self, operation: str):
        """Inicia operação de criptografia, descriptografia ou verificação."""
        try:
            path = self.file_input.text().strip()
            if not path:
                self.status_bar.showMessage("Select a file first.")
                return
            pwd = self.password_input.text()
            if not pwd:
                self.status_bar.showMessage("Enter a password.")
                return

            if not self._guard_password_whitespace(pwd, "Senha inválida"):
                return

            self._is_encrypt = operation == "encrypt"
            self._is_verify = operation == "verify"

            self._original_path = path
            src = path
            self._tmp_zip = None
            self._forced_out = ""
            src_path = Path(src)

            if src_path.is_dir():
                if not self._is_encrypt:
                    QMessageBox.warning(
                        self,
                        "Invalid Selection",
                        "Please select a file for decrypt/verify.",
                    )
                    self.status_bar.showMessage("Select a file for decrypt/verify.")
                    return
                if not self.check_archive.isChecked():
                    QMessageBox.information(
                        self,
                        "Auto-Archive",
                        "Folders require ZIP archiving for encryption. Enabling automatically.",
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
            kdf_profile = (
                "INTERACTIVE"
                if self.combo_profile.currentText().lower().startswith("inter")
                else "SENSITIVE"
            )

            if self._is_encrypt:
                self.status_bar.showMessage(f"Encrypting with {alg_name}")
            elif self._is_verify:
                try:
                    ver = read_header_version_any(src)
                    self.status_bar.showMessage(
                        "Verifying CG2 v5 (SecretStream)" if ver >= 5 else "Verifying legacy CG2"
                    )
                except Exception:
                    self.status_bar.showMessage("Verifying (unknown format)")
            else:
                try:
                    ver = read_header_version_any(src)
                    self.status_bar.showMessage(
                        "Decrypting CG2 v5 (SecretStream)" if ver >= 5 else "Decrypting legacy CG2"
                    )
                except Exception:
                    self.status_bar.showMessage("Decrypting (unknown format)")

            delete_flag = self.check_delete.isChecked()
            if self._is_verify:
                delete_flag = False
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
                # padroniza nome do parâmetro com factories
                extra["exp_ts"] = int(exp_dt.timestamp())

            if self._is_encrypt:
                # mapeia para tamanho numérico (0/4096/16384) usado pelo writer
                pad_name = self.combo_padding.currentText().lower().replace(" ", "")
                pad_map = {"off": 0, "4kb": 4096, "16kb": 16384}
                extra["pad_block"] = pad_map.get(pad_name, 0)
                extra["kdf_profile"] = kdf_profile
                # destino: pasta fixa se habilitada; caso contrário ao lado do arquivo
                if self._forced_out:
                    extra["out_path"] = self._forced_out
                else:
                    dest_name = Path(src).with_suffix(".cg2").name
                    if bool(self._settings.get("fixed_out_enabled", False)):
                        base = Path(str(self._settings.get("fixed_out_dir", "") or "")).expanduser()
                        try:
                            base.mkdir(parents=True, exist_ok=True)
                            extra["out_path"] = str(base / dest_name)
                        except Exception:
                            # fallback para pasta do arquivo
                            extra["out_path"] = str(Path(src).with_suffix(".cg2"))
                    else:
                        extra["out_path"] = str(Path(src).with_suffix(".cg2"))
                extra["hide_filename"] = self.check_hide_filename.isChecked()
            elif self._is_verify:
                extra["verify_only"] = True

            if not hasattr(self, "_operation_size"):
                self._operation_size = src_size

            # Bloqueio anti-bruteforce (se criptografia NÃO; apenas antes de decrypt)
            if (not self._is_encrypt) and path in self._lockout_until and time.time() < self._lockout_until[path]:
                wait_s = int(self._lockout_until[path] - time.time())
                self.status_bar.showMessage(
                    f"Too many attempts for {path.name} — wait {wait_s}s.", 5000
                )
                return

            # Pré-cheque da API SecretStream (fail-fast em ambientes com PyNaCl inconsistente)
            if self._is_encrypt:
                ok, msg = self._secretstream_preflight(silent=True)
                if not ok:
                    self.status_bar.showMessage(msg or "SecretStream preflight failed.")
                    QMessageBox.critical(
                        self, "SecretStream", msg or "SecretStream preflight failed."
                    )
                    return

            # Disable UI & prepare progress
            self._toggle(False)
            self.progress_bar.setMaximum(0)
            self.progress_bar.setValue(0)
            self.status_bar.showMessage("Deriving key (Argon2)…")

            self.worker = CryptoWorker(operation, src, pwd, delete_flag, extra)
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

        if not self._guard_password_whitespace(pwd, "Senha inválida"):
            return

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
                self._cancel_timer = QTimer(self)
                self._cancel_timer.timeout.connect(self.worker.quit)
                self._cancel_timer.start(100)
                self.worker.wait(1000)

            self.status_bar.showMessage("Operation cancelled.", 5000)
            self.btn_cancel.setEnabled(False)
            self._toggle(True)

            if self._tmp_zip:
                with contextlib.suppress(Exception):
                    os.remove(self._tmp_zip)

            # Worker handles cleanup internally; just signal finish
            self._is_verify = False
            self.worker.finished.emit("")
            if self._cancel_timer:
                with contextlib.suppress(Exception):
                    self._cancel_timer.stop()
                self._cancel_timer = None

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
            if (not self._is_encrypt) and getattr(self, "_is_verify", False):
                self.progress_bar.setValue(100)
                if self._cancel_timer:
                    with contextlib.suppress(Exception):
                        self._cancel_timer.stop()
                    self._cancel_timer = None
                if hasattr(self, "_tmp_zip") and self._tmp_zip:
                    Path(self._tmp_zip).unlink(missing_ok=True)
                self.status_bar.showMessage("Integrity OK.", 5000)
                QMessageBox.information(
                    self,
                    "Success",
                    "Integrity OK. Password is correct and file is not corrupt.",
                )
                if self._original_path:
                    self._failed_attempts.pop(self._original_path, None)
                    self._lockout_until.pop(self._original_path, None)
                if hasattr(self, "_operation_size"):
                    delattr(self, "_operation_size")
                self._is_verify = False
                self._toggle(True)
                return
            self.status_bar.showMessage("Operation cancelled.", 5000)
            self._toggle(True)
            return

        self.progress_bar.setValue(100)
        if self._cancel_timer:
            with contextlib.suppress(Exception):
                self._cancel_timer.stop()
            self._cancel_timer = None

        # Limpa ZIP temporÃ¡rio
        if hasattr(self, "_tmp_zip") and self._tmp_zip:
            Path(self._tmp_zip).unlink(missing_ok=True)

        final_output = out_path

        # PATCH 7.2: Extração automÃ¡tica pós-decrypt
        if (
            not self._is_encrypt
            and self.check_extract.isChecked()
            and out_path.endswith(".zip")
            and zipfile.is_zipfile(out_path)
        ):
            dest_dir = Path(out_path).with_suffix("")
            try:
                with zipfile.ZipFile(out_path, "r") as zf:
                    zf.extractall(dest_dir)
                self.status_bar.showMessage(f"ZIP extracted to {dest_dir}", 5000)
            except Exception as exc:
                logger.exception("Auto-extract failed: %s", exc)

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
                    self, "Success", "File encrypted and moved to Vault successfully."
                )
            except Exception as e:
                QMessageBox.warning(self, "Vault", f"Could not store file in Vault:\n{e}")
                QMessageBox.information(self, "Success", f"Output file:\n{Path(final_output).name}")
        else:
            QMessageBox.information(self, "Success", f"Output file:\n{Path(final_output).name}")

        # Secure-delete (checkbox manual OU auto-delete após encryptação)
        should_delete = False
        if self.check_delete.isChecked():
            should_delete = True
        elif self._is_encrypt and self._settings.get("hygiene_delete_original", False):
            # Auto-delete após encriptação (se habilitado nas configs)
            should_delete = True
        
        if should_delete and self._original_path:
            try:
                p = Path(self._original_path)
                
                # Check if SSD and warn user
                if is_ssd(p):
                    msg = (
                        f"WARNING: File is on SSD/NVMe storage.\n\n"
                        f"Secure deletion is NOT fully effective on SSDs due to wear leveling.\n"
                        f"The file will be deleted, but data may remain in spare cells.\n\n"
                        f"For maximum security, use full-disk encryption (BitLocker, LUKS, etc.)"
                    )
                    reply = QMessageBox.warning(
                        self,
                        "SSD Detection",
                        msg,
                        QMessageBox.Ok | QMessageBox.Cancel,
                        QMessageBox.Ok
                    )
                    if reply != QMessageBox.Ok:
                        self.status_bar.showMessage("Secure deletion cancelled.", 5000)
                        should_delete = False
                
                if should_delete:
                    passes = self._settings.get("hygiene_passes", 3)
                    if p.is_dir():
                        shutil.rmtree(p, ignore_errors=True)
                        self.status_bar.showMessage(f"Directory deleted: {p.name}", 5000)
                    else:
                        success = secure_delete_file(p, passes=passes)
                        if success:
                            self.status_bar.showMessage(
                                f"Original file securely deleted ({passes} pass{'es' if passes > 1 else ''})", 
                                5000
                            )
                        else:
                            self.status_bar.showMessage(f"Delete failed for: {p.name}", 8000)
                            
            except Exception as e:
                logger.warning("Secure delete failed: %s", e)
                self.status_bar.showMessage(f"Delete failed: {e}", 8000)

        if not self._is_encrypt and self._original_path:
            self._failed_attempts.pop(self._original_path, None)
            self._lockout_until.pop(self._original_path, None)

        self.status_bar.showMessage("Done.", 8000)

        # Limpa _operation_size
        if hasattr(self, "_operation_size"):
            delattr(self, "_operation_size")

        self._is_verify = False
        self._toggle(True)

    def _operation_error(self, msg: str):
        """Erro na operação."""
        if self._cancel_timer:
            with contextlib.suppress(Exception):
                self._cancel_timer.stop()
            self._cancel_timer = None
        # Rate limiting tracking for failed decrypts
        if not self._is_encrypt:
            with contextlib.suppress(Exception):
                path_key = self._original_path
                self._failed_attempts[path_key] = self._failed_attempts.get(path_key, 0) + 1
                if self._failed_attempts[path_key] >= 5:
                    self._lockout_until[path_key] = time.time() + 300
        if getattr(self, "_tmp_zip", None):
            with contextlib.suppress(Exception):
                os.remove(self._tmp_zip)

        # Traduz erros comuns
        if "InvalidTag" in msg or "MAC check failed" in msg:
            msg = "Senha ou arquivo incorretos."
        else:
            low = msg.lower()
            if "expired" in low:
                msg = "Arquivo expirado, não pode ser descriptografado."
            elif "requires keyfile" in low:
                msg = "Este arquivo exige keyfile. Selecione o keyfile correto e tente novamente."
        if (
            "PyNaCl/libsodium mismatch" in msg
            or "SecretStream init failed" in msg
            or "SecretStream API mismatch" in msg
        ):
            msg += "\nSugestão: pip install -U --force-reinstall 'pynacl>=1.5.0'"

        QMessageBox.critical(self, "Erro", msg)
        self.status_bar.showMessage(f"Error: {msg}", 10000)

        # Limpa _operation_size
        if hasattr(self, "_operation_size"):
            delattr(self, "_operation_size")

        self._is_verify = False
        self._toggle(True)

    # --- MOVIDO PARA CIMA & TORNADO NÃƒO BLOQUEANTE ---
    def _secretstream_preflight(self, silent: bool = False) -> tuple[bool, str]:
        """
        Verifica se a API crypto_secretstream_xchacha20poly1305_init_push tem a
        assinatura esperada (1 arg: key). Em versÃµes legadas pode exigir 2 args
        (header, key) ou outra forma â€" não suportada pelo xchacha_stream atual.
        Retorna (ok, mensagem_de_erro_ou_vazia).
        """
        try:

            func = nb.crypto_secretstream_xchacha20poly1305_init_push
            sig = inspect.signature(func)
            # Assinatura moderna (1 param) ou estilo C (2 params) - ambas suportadas
            if len(sig.parameters) in (1, 2):
                # Teste básico da função (ambas as assinaturas são compatíveis)
                try:
                    if len(sig.parameters) == 1:
                        # API moderna: init_push(key) -> (state, header)
                        func(b"\x00" * 32)
                    else:
                        # API estilo C: init_push(state, key) -> header
                        state = crypto_secretstream_xchacha20poly1305_state()
                        func(state, b"\x00" * 32)
                except Exception as exc:
                    logger.debug(
                        "SecretStream preflight test failed during init_push: %s", exc
                    )
                return True, ""
            # Assinatura inesperada
            msg = (
                f"Incompatible SecretStream API (expected 1 or 2 params, got {len(sig.parameters)}). "
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
                self, "Vault Password", "Digite a senha do Vault:", QLineEdit.Password
            )
            if not ok or not pw:
                return
            if password_whitespace_hint(pw):
                QMessageBox.warning(
                    self,
                    "Senha inválida",
                    "A senha contém espaços em branco extras. Remova-os e tente novamente.",
                )
                continue
            try:
                vault_path = Config.default_vault_path()
                if vault_path.exists() and vault_path.stat().st_size == 0:
                    vault_path.unlink()
                exists = vault_path.exists()
                if not exists:
                    # Confirmar criação explícita para evitar criar com senha errada por engano
                    if (
                        QMessageBox.question(
                            self,
                            "Criar Vault",
                            f"Nenhum vault encontrado em:\n{vault_path}\n\nDeseja criar um novo?",
                            QMessageBox.Yes | QMessageBox.No,
                            QMessageBox.No,
                        )
                        != QMessageBox.Yes
                    ):
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
                if (
                    QMessageBox.question(
                        self,
                        "Vault corrompido",
                        "O arquivo vault3.dat parece corrompido.\nDeseja sobrescrevÃª-lo?",
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No,
                    )
                    == QMessageBox.Yes
                ):
                    vault_path.unlink(missing_ok=True)
                    continue
                else:
                    return
            except WrongPassword as e:
                logger.vault_error(
                    "open",
                    "CryptGuard",
                    e,
                    {
                        "vault_path": str(vault_path),
                        "ui_context": "main_app_open_vault",
                    },
                )
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
            self, "Senha atual", "Digite a senha atual:", QLineEdit.Password
        )
        if not ok or not old_pw:
            return

        new_pw, ok2 = QInputDialog.getText(
            self, "Nova senha", "Digite a nova senha:", QLineEdit.Password
        )
        if not ok2 or not new_pw:
            return

        confirm, ok3 = QInputDialog.getText(
            self, "Confirme a nova senha", "Repita a nova senha:", QLineEdit.Password
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

    # ───────────────────────────── Settings (UI + persistência) ─────────────────────────────
    def _load_settings(self) -> dict:
        try:

            if SETTINGS_PATH.exists():
                return json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to load settings: %s", exc)
        # defaults
        return {
            "clipboard_autoclear": True,  # limpa em 30s
            "fixed_out_enabled": False,  # usar diretório fixo?
            "fixed_out_dir": "",  # caminho do diretório
            # Higiene de arquivos
            "hygiene_delete_original": HYGIENE_DEFAULT_SETTINGS["delete_original_after_encrypt"],
            "hygiene_clean_startup": HYGIENE_DEFAULT_SETTINGS["clean_temp_on_startup"],
            "hygiene_clean_shutdown": HYGIENE_DEFAULT_SETTINGS["clean_temp_on_shutdown"],
            "hygiene_passes": HYGIENE_DEFAULT_SETTINGS["secure_delete_passes"],
        }

    def _save_settings(self, data: dict) -> None:
        try:

            SETTINGS_PATH.write_text(
                json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except Exception as e:
            self.status_bar.showMessage(f"Could not save settings: {e}", 8000)

    # ───────────────────────────── Higiene de Arquivos ─────────────────────────────
    
    def _cleanup_temp_on_startup(self) -> None:
        """Limpa temporários antigos na inicialização (non-blocking)."""
        try:
            files_removed, bytes_freed = cleanup_temp_folder(max_age_hours=24, dry_run=False)
            if files_removed > 0:
                size_mb = bytes_freed / (1024 * 1024)
                logger.info(f"Startup cleanup: removed {files_removed} temp file(s), freed {size_mb:.2f} MB")
                self.status_bar.showMessage(
                    f"Cleaned {files_removed} temporary file(s) ({size_mb:.1f} MB)", 4000
                )
        except Exception as exc:
            logger.warning("Startup temp cleanup failed: %s", exc)

    def _cleanup_temp_on_shutdown(self) -> None:
        """Limpa temporários recentes no encerramento (quick cleanup)."""
        try:
            # Cleanup mais agressivo: arquivos com mais de 1 hora
            files_removed, _ = cleanup_temp_folder(max_age_hours=1, dry_run=False)
            if files_removed > 0:
                logger.info(f"Shutdown cleanup: removed {files_removed} temp file(s)")
        except Exception as exc:
            logger.warning("Shutdown temp cleanup failed: %s", exc)

    def _manual_cleanup_temp(self) -> None:
        """Limpeza manual de temporários (com confirmação)."""
        try:
            manager = TempFolderManager()
            manager.ensure_dirs()
            stats = manager.get_temp_stats()
            
            if stats["file_count"] == 0:
                QMessageBox.information(
                    self,
                    "Temp Cleanup",
                    "No temporary files to clean."
                )
                return
            
            size_mb = stats["total_bytes"] / (1024 * 1024)
            msg = (
                f"Found {stats['file_count']} temporary file(s) "
                f"using {size_mb:.2f} MB.\n\n"
                f"Do you want to delete these files?"
            )
            
            reply = QMessageBox.question(
                self,
                "Clean Temporary Files",
                msg,
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply != QMessageBox.Yes:
                return
            
            # Perform cleanup
            files_removed, bytes_freed = cleanup_temp_folder(max_age_hours=0, dry_run=False)
            size_freed_mb = bytes_freed / (1024 * 1024)
            
            QMessageBox.information(
                self,
                "Cleanup Complete",
                f"Removed {files_removed} file(s), freed {size_freed_mb:.2f} MB"
            )
            self.status_bar.showMessage(f"Cleaned {files_removed} temp file(s)", 5000)
            
        except Exception as exc:
            logger.exception("Manual temp cleanup failed")
            QMessageBox.warning(
                self,
                "Cleanup Error",
                f"Failed to clean temporary files:\n{exc}"
            )

    def closeEvent(self, event):
        """Handle window close event with optional temp cleanup."""
        try:
            # Cleanup de temporários no encerramento (se habilitado)
            if self._settings.get("hygiene_clean_shutdown", True):
                self._cleanup_temp_on_shutdown()
        except Exception as exc:
            logger.warning("Shutdown cleanup failed: %s", exc)
        finally:
            event.accept()

    def open_settings(self):
        dlg = SettingsDialog(self, self._settings)
        if dlg.exec() == QDialog.Accepted:
            self._settings = dlg.result_settings
            self._save_settings(self._settings)
            self.status_bar.showMessage("Settings saved.", 5000)

    def _open_log(self):
        """Abre o arquivo de log no editor padrão."""
        try:
            for h in getattr(logger, "handlers", []):
                with contextlib.suppress(Exception):
                    h.flush()

            try:
                LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
                LOG_PATH.touch(exist_ok=True)
            except Exception as exc:
                logger.warning("Could not prepare log file %s: %s", LOG_PATH, exc)

            # Qt
            if QDesktopServices.openUrl(QUrl.fromLocalFile(str(LOG_PATH))):
                return

            # Windows
            if sys.platform.startswith("win"):
                try:
                    os.startfile(str(LOG_PATH))
                    return
                except Exception as exc:
                    logger.debug("os.startfile failed for log %s: %s", LOG_PATH, exc)

            # Unix
            for cmd in ("xdg-open", "open"):
                try:
                    subprocess.Popen([cmd, str(LOG_PATH)])
                    return
                except Exception:
                    continue

            QMessageBox.information(self, "Log", f"Log file:\n{LOG_PATH}")
        except Exception as e:
            QMessageBox.warning(
                self,
                "Log",
                f"Não foi possÃ­vel abrir o log:\n{e}\n\nCaminho: {LOG_PATH}",
            )

    def _show_about(self):
        """Mostra diÃ¡logo Sobre (paridade com main_app.py)."""
        ver = getattr(self, "APP_VERSION", "3.0")
        QMessageBox.about(
            self,
            "Sobre o CryptGuardv2",
            (
                "<h3>CryptGuardv2</h3>"
                f"<p>Version {ver}</p>"
                "<p>Modern, auditable file encryption with a unified v5 pipeline.</p>"
                "<p><b>Highlights:</b></p>"
                "<ul>"
                "<li><b>Container v5</b> with header-bound AAD and canonical JSON</li>"
                "<li>Streaming <b>XChaCha20-Poly1305</b> (libsodium SecretStream)</li>"
                "<li><b>Argon2id</b> profiles tuned by target time</li>"
                "<li>Atomic writes and fsync for crash resilience</li>"
                "<li>Optional <b>padding</b> to hide plaintext size</li>"
                "<li>Support for <b>password + keyfile</b></li>"
                "<li><b>Vault</b> integration for encrypted item management</li>"
                "<li>Redacted logs; verify-only mode leaves no plaintext</li>"
                "</ul>"
                "<p>&copy; 2024–2025 CryptGuard Team</p>"
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
        except Exception as exc:
            logger.debug("Failed to compact layout: %s", exc)

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
        row = QHBoxLayout()
        self._compact(row, 8)
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
        kdf_row = QHBoxLayout()
        self._compact(kdf_row, 8)
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
        pad_row = QHBoxLayout()
        self._compact(pad_row, 8)
        pad_label = QLabel("Pad size", self)
        pad_label.setStyleSheet("font-weight: 600; color: #e6eaf0;")
        pad_label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        pad_row.addWidget(pad_label)
        self.combo_padding = QComboBox(self)
        self.combo_padding.addItems(
            ["Off", "4 KB", "16 KB"]
        )  # mapeia para 4k/16k no start_operation
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
        exp_row = QHBoxLayout()
        self._compact(exp_row, 8)
        exp_date_label = QLabel("Expiration date", self)
        exp_date_label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        exp_row.addWidget(exp_date_label)
        self.date_expiration = ClickableDateEdit(self)
        self.date_expiration.setMinimumWidth(100)
        self.date_expiration.setDate(QDate.currentDate())
        self.date_expiration.setCalendarPopup(True)
        exp_row.addWidget(self.date_expiration)
        self.check_expiration = QCheckBox("Enable expiration date", self)
        exp_row.addWidget(self.check_expiration)
        exp_row.addStretch(1)
        lv.addLayout(exp_row)
        lv.addSpacing(6)

        # Password + Show
        p_row = QHBoxLayout()
        self._compact(p_row, 8)
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
        kf_row = QHBoxLayout()
        self._compact(kf_row, 8)
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
        for cb in (
            self.check_hide_filename,
            self.check_delete,
            self.check_archive,
            self.check_vault,
            self.check_extract,
        ):
            lv.addWidget(cb)
        # dá mais corpo à coluna de opções antes dos botões
        lv.addSpacing(6)

        # Botões de ação (sem alterar rótulos)
        btn_row = QHBoxLayout()
        self._compact(btn_row, 10)
        self.btn_encrypt = QPushButton(" Encrypt", self)
        self.btn_decrypt = QPushButton(" Decrypt", self)
        self.btn_verify = QPushButton(" Verify", self)
        self.btn_cancel = QPushButton(" Cancel", self)

        self.btn_encrypt.setIcon(qta.icon("fa5s.lock", color="#e6eaf0"))
        self.btn_decrypt.setIcon(qta.icon("fa5s.unlock", color="#e6eaf0"))
        self.btn_verify.setIcon(qta.icon("fa5s.check", color="#e6eaf0"))
        self.btn_cancel.setIcon(qta.icon("fa5s.times", color="#e6eaf0"))

        self.btn_encrypt.setObjectName("mainActionButton")
        self.btn_decrypt.setObjectName("mainActionButton")
        self.btn_verify.setObjectName("mainActionButton")
        self.btn_cancel.setObjectName("cancelButton")

        self.btn_encrypt.clicked.connect(lambda: self._start_operation("encrypt"))
        self.btn_decrypt.clicked.connect(lambda: self._start_operation("decrypt"))
        self.btn_verify.clicked.connect(lambda: self._start_operation("verify"))
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
        footer = QHBoxLayout()
        self._compact(footer, 10)
        footer.addStretch(1)  # empurra tudo para a direita
        self.btn_log = QPushButton(" Log", self)
        self.btn_log.setIcon(qta.icon("fa5s.file-alt", color="#9aa3b2"))
        self.btn_log.setObjectName("footerButton")
        self.btn_log.clicked.connect(self._open_log)
        footer.addWidget(self.btn_log)

        self.btn_change_pw = QPushButton(" Change Password", self)
        self.btn_change_pw.setIcon(qta.icon("fa5s.key", color="#9aa3b2"))
        self.btn_change_pw.setObjectName("footerButton")
        self.btn_change_pw.clicked.connect(self._change_vault_password)
        footer.addWidget(self.btn_change_pw)

        self.btn_vault = QPushButton(" Vault", self)
        self.btn_vault.setIcon(qta.icon("fa5s.database", color="#9aa3b2"))
        self.btn_vault.setObjectName("footerButton")
        self.btn_vault.clicked.connect(self._open_vault)
        footer.addWidget(self.btn_vault)

        self.btn_settings = QPushButton(" Settings", self)
        self.btn_settings.setIcon(qta.icon("fa5s.cog", color="#9aa3b2"))
        self.btn_settings.setObjectName("footerButton")
        self.btn_settings.clicked.connect(self.open_settings)
        footer.addWidget(self.btn_settings)

        lv.addLayout(footer)

        # Widgets "de linha" com altura fixa
        for w in (
            kdf_label,
            self.combo_profile,
            pad_label,
            self.combo_padding,
            self.date_expiration,
            self.check_expiration,
            self.password_input,
            self.btn_show_password,
            self.check_keyfile,
            self.keyfile_input,
            self.btn_pick_keyfile,
            self.check_hide_filename,
            self.check_delete,
            self.check_archive,
            self.check_vault,
            self.check_extract,
        ):
            w.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)

        # Campos e combos não devem crescer na vertical
        for w in (
            self.file_input,
            self.password_input,
            self.keyfile_input,
            self.combo_profile,
            self.combo_padding,
            self.date_expiration,
        ):
            w.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        # Progress bar um pouco mais baixa (coerente com o CSS acima)
        self.progress_bar.setFixedHeight(14)

        # Botões com altura mínima menor
        for b in (
            self.btn_encrypt,
            self.btn_decrypt,
            self.btn_verify,
            self.btn_cancel,
            self.btn_log,
            self.btn_change_pw,
            self.btn_vault,
            self.btn_settings,
        ):
            b.setMinimumHeight(28)

        # Anexa painel esquerdo e reserva espaço à direita p/ KeyGuard
        self.body_layout.addWidget(left, 1)  # fixa ao topo
        # (KeyGuard entra depois pelo _ensure_keyguard)

        # Status bar
        self.status_bar = QStatusBar(self)
        root.addWidget(self.status_bar)


# ------------------------------------------------------------------------------------------------------------------------------â•â•
#                              MAIN ENTRY POINT
# ------------------------------------------------------------------------------------------------------------------------------â•â•



# Handler global de exceções para capturar todos os erros
def global_exception_handler(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    # Registra com traceback completo
    logger.error("Exceção não tratada", exc_info=(exc_type, exc_value, exc_traceback))


sys.excepthook = global_exception_handler


def main() -> None:
    """Entry-point for the legacy Qt UI."""
    QCoreApplication.setOrganizationName(PLATFORM_ORG_NAME)
    if hasattr(QCoreApplication, "setOrganizationDomain"):
        QCoreApplication.setOrganizationDomain("cryptguard.dev")
    QCoreApplication.setApplicationName(PLATFORM_APP_NAME)
    try:
        from PySide6.QtGui import QGuiApplication

        if hasattr(QGuiApplication, "setApplicationDisplayName"):
            QGuiApplication.setApplicationDisplayName(PLATFORM_APP_NAME)
    except Exception:
        pass
    if IS_LINUX:
        try:
            harden_process_best_effort_linux()
        except Exception as exc:
            logger.debug("Linux process hardening skipped: %s", exc)
    try:
        from crypto_core.config import enable_process_hardening
        from crypto_core.memharden import harden_process_best_effort
        from crypto_core.paths import ensure_base_dir

        ensure_base_dir()
        enable_process_hardening()
        harden_process_best_effort()
    except Exception:
        # best-effort hardening; ignore failures to keep UI usable
        pass

    try:
        app = QApplication(sys.argv)
    except Exception:
        if IS_LINUX:
            print("Falha ao inicializar backend Qt (Wayland/XCB). Verifique dependências do sistema.")
            explain_qpa_failure()
        raise

    try:
        _tr = QTranslator()
        if _tr.load(QLocale.system(), "cryptguard", "_", "i18n"):
            app.installTranslator(_tr)
    except Exception as exc:
        logger.debug("Translator installation skipped: %s", exc)

    win = MainWindow()
    try:
        app.aboutToQuit.connect(win._clear_clipboard_if_unchanged)
    except Exception as exc:
        logger.debug("Failed to connect aboutToQuit handler: %s", exc)

    win.show()
    if IS_WIN:
        try:
            hwnd = int(win.winId())
            try_enable_dark_titlebar(hwnd)
            try_enable_mica(hwnd)
        except Exception as exc:
            logger.debug("Windows effects not applied: %s", exc)

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
