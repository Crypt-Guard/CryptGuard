"""crypto_core/__init__.py – bootstrap compacto v3 (pós-refatoração)

Responsabilidades principais
────────────────────────────
1. Verificar dependências mínimas e inicializar logging/banco de dados.
2. Processar flags globais de CLI (**--calibrate-kdf**, **--harden**).
3. Carregar (ou autodetectar) calibração Argon2id.
4. Expor a API pública simplificada baseada em fábricas:

   • `encrypt(path, password, algo="AES-GCM", **kw)` - routes to CG2
   • `decrypt(path, password, **kw)` - auto-detects CG2 vs legacy
   • `get_cipher(tag, streaming=None)`
   • constantes `SecurityProfile`, `LOG_PATH`

Todo o roteamento de algoritmos agora é delegado a `factories.py`.
"""
from __future__ import annotations

import sys, argparse
from importlib import util
from pathlib import Path

from .paths import LOG_PATH
from .logger import logger  # inicializa logger
from .config import enable_process_hardening, SecurityProfile, ARGON_PARAMS, READ_LEGACY_FORMATS
from .argon_utils import load_calibrated_params, calibrate_kdf
from .factories import get_cipher  # API de baixo nível
from .fileformat import is_cg2_file
from .cg2_ops import encrypt_to_cg2, decrypt_from_cg2

# Define the CG2 file extension constant if not already present
CG2_EXT = ".cg2"

# Optional legacy module loader
try:
    from . import legacy
    decrypt_legacy = legacy.decrypt_legacy
except (ImportError, AttributeError):
    # Create a simple fallback that uses existing decrypt logic
    def decrypt_legacy(in_path, out_path, password):
        raise NotImplementedError("Legacy decrypt not implemented - create legacy.py module")

# ─── dependências mínimas ────────────────────────────────────────────────
_REQ = {"psutil", "argon2", "reedsolo", "PySide6", "cryptography"}
_missing = [pkg for pkg in _REQ if util.find_spec(pkg) is None]
if _missing:
    logger.critical(f"Dependências ausentes: {_missing}. Instale e tente novamente.")
    sys.exit(1)

# ─── flags globais (--calibrate-kdf, --harden) ───────────────────────────
_ap = argparse.ArgumentParser(add_help=False)
_ap.add_argument("--calibrate-kdf", action="store_true",
                help="calibra Argon2id para ~0,5 s")
_ap.add_argument("--harden", action="store_true",
                help="ativa proteções de processo (mlock, anti-debug)")
_args, _ = _ap.parse_known_args()

if _args.calibrate_kdf:
    calibrate_kdf()
    print("Calibração Argon2 concluída.")
    sys.exit(0)
if _args.harden:
    try:
        enable_process_hardening()
        print("Hardening de processo ativado.")
    except Exception as e:
        logger.warning("Falha ao ativar hardening: %s", e)

# ─── calibração Argon2id ─────────────────────────────────────────────────
try:
    load_calibrated_params()
except Exception as e:
    logger.info("Argon2 calibrado automaticamente falhou (%s); usando defaults.", e)

# ─── API pública de alto nível ───────────────────────────────────────────
def encrypt(
    in_path: str | Path,
    password: str | bytes,
    *,
    alg: str = "AES-256-GCM",
    profile: SecurityProfile = SecurityProfile.BALANCED,
    expires_at: int | None = None,
    exp_ts: int | None = None,   # compat
    progress_cb=None,
    pad_block: int = 0,          # ⬅ padding opcional por chunk
) -> Path:
    """Encrypt → .cg2 no mesmo diretório (destino automático)."""
    if isinstance(password, str):
        password = password.encode()
    in_path = Path(in_path)
    out_path = in_path.with_suffix(CG2_EXT)
    if expires_at is None:
        expires_at = exp_ts
    return encrypt_to_cg2(
        in_path, out_path, password, alg, profile, expires_at,
        progress_cb=progress_cb, pad_block=pad_block
    )

def decrypt(
    in_path: str | Path,
    password: str | bytes,
    *,
    progress_cb=None,
) -> Path:
    """Decrypt: para CG2 delega a escolha da extensão ao cg2_ops (magic)."""
    in_path = Path(in_path)
    pwd = password.encode() if isinstance(password, str) else password

    if is_cg2_file(in_path):
        # remove .cg2; cg2_ops decidirá a extensão correta pelo magic do plaintext
        base = in_path.with_suffix("") if in_path.suffix.lower() == CG2_EXT else in_path.with_suffix(".dec")
        return decrypt_from_cg2(in_path, base, pwd, verify_only=False, progress_cb=progress_cb)

    if READ_LEGACY_FORMATS:
        raise NotImplementedError("Decrypt legado desativado nesta build")
    raise ValueError("Unknown file format and legacy support disabled")


__all__ = [
    "encrypt", "decrypt", "get_cipher",
    "SecurityProfile", "LOG_PATH",
]
