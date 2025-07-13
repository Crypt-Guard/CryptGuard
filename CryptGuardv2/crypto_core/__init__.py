"""
Inicialização global do CryptGuard v2 + utilidades CLI.

• Checagem de dependências mínimas
• Carregamento de calibração Argon2, se existir
• Flags:
    --calibrate-kdf   → ajusta parâmetros Argon2id (~75 % da RAM)
    --harden          → ativa ProcessProtection (mlockall, anti-ptrace, etc.)

Também expõe as funções públicas de criptografia/descriptografia
(AES-GCM e ChaCha20, single-shot ou streaming).
"""
from __future__ import annotations
import sys, argparse, importlib
from pathlib import Path

from .logger             import logger, warn_critical
from .config             import ARGON_PARAMS, SecurityProfile, LOG_PATH, load_calibrated_params, calibrate_kdf, enable_process_hardening
from .database import init_db

# Inicializar banco de dados
init_db()

# ─── dependências mínimas ───────────────────────────────────────────────
_REQ = {"psutil", "argon2", "reedsolo", "PySide6", "cryptography"}
_missing = [pkg for pkg in _REQ if importlib.util.find_spec(pkg) is None]
if _missing:
    warn_critical(f"Dependências ausentes: {_missing}. Instale-as e execute novamente.")
    sys.exit(1)

# ─── calibração Argon2 (se foi rodada anteriormente) ───────────────────
load_calibrated_params()

# ─── CLI flags globais (executadas cedo) ───────────────────────────────
def _cli():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--calibrate-kdf", action="store_true", help="calibra Argon2id para ~0,5 s")
    ap.add_argument("--harden",       action="store_true", help="ativa ProcessProtection")
    args, _ = ap.parse_known_args()
    if args.calibrate_kdf:
        calibrate_kdf()
        print("Calibração concluída (parâmetros salvos).")
        sys.exit(0)
    if args.harden:
        enable_process_hardening()

_cli()

# ─── exportação da API pública do core ─────────────────────────────────
from .file_crypto                 import encrypt_file   as encrypt_aes,    decrypt_file   as decrypt_aes
from .file_crypto_chacha          import encrypt_file   as encrypt_chacha, decrypt_file   as decrypt_chacha
from .file_crypto_chacha_stream   import encrypt_file   as encrypt_chacha_stream, \
                                          decrypt_file   as decrypt_chacha_stream

__all__ = [
    "SecurityProfile", "LOG_PATH",
    "encrypt_aes", "decrypt_aes",
    "encrypt_chacha", "decrypt_chacha",
    "encrypt_chacha_stream", "decrypt_chacha_stream",
]
