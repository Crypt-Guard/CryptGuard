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
from .file_crypto_ctr             import encrypt_file   as encrypt_ctr,    decrypt_file   as decrypt_ctr

# expose friendly wrapper ------------------------------------------------
def encrypt(path: str, password: str, algo: str = "AES", **kw) -> str:
    """
    One-liner helper. *algo* = AES, AESCTR, CHACHA, XCHACHA.
    """
    algo = algo.upper()
    if algo == "AES":
        return encrypt_aes(path, password, **kw)
    if algo == "AESCTR":
        return encrypt_ctr(path, password, **kw)
    if algo == "CHACHA":
        return encrypt_chacha(path, password, **kw)

    raise ValueError("unknown algorithm")

def decrypt(path: str, password: str, **kw) -> str:
    from pathlib import Path
    ext = Path(path).suffix.upper()
    if ext.endswith(".ENC"):
        tag = Path(path).read_bytes()[20:24]
        if tag == b"AESG":
            return decrypt_aes(path, password, **kw)
        if tag == b"ACTR":
            return decrypt_ctr(path, password, **kw)
        if tag in (b"CH20", b"CHS3"):
            return decrypt_chacha(path, password, **kw)

    raise ValueError("Cannot determine algorithm; pass explicit backend.")

__all__ = [
    "SecurityProfile", "LOG_PATH",
    "encrypt_aes", "decrypt_aes",
    "encrypt_chacha", "decrypt_chacha",
    "encrypt_chacha_stream", "decrypt_chacha_stream",
    "encrypt", "decrypt",
]
