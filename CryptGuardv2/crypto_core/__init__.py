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
from .config import enable_process_hardening, SecurityProfile, ARGON_PARAMS
from .argon_utils import load_calibrated_params, calibrate_kdf
from .fileformat import is_cg2_file

# Garanta constantes esperadas no módulo config antes de qualquer importação pesada
from . import config as _cfg  # type: ignore
if not hasattr(_cfg, "ENC_EXT"):
    _cfg.ENC_EXT = ".cg2"
if not hasattr(_cfg, "CG2_EXT"):
    _cfg.CG2_EXT = _cfg.ENC_EXT
if not hasattr(_cfg, "META_EXT"):
    _cfg.META_EXT = ".meta"

# Use unified extension from config
CG2_EXT = _cfg.ENC_EXT

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
    logger.warning(f"Dependências ausentes (opcionais para core): {_missing} — continuando com funcionalidades limitadas.")

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
    pass
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
def get_cipher(tag, streaming=None):
    # Importa sob demanda para evitar ImportError durante bootstrap
    from .factories import get_cipher as _get_cipher
    return _get_cipher(tag, streaming=streaming)

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
    # Importa sob demanda para garantir que config já tenha constantes fallback
    from .cg2_ops import encrypt_to_cg2
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
    # Importa sob demanda para garantir que config já tenha constantes fallback
    from .cg2_ops import decrypt_from_cg2
    in_path = Path(in_path)
    pwd = password.encode() if isinstance(password, str) else password

    if is_cg2_file(in_path):
        # remove .cg2; cg2_ops decidirá a extensão correta pelo magic do plaintext
        base = in_path.with_suffix("") if in_path.suffix.lower() == CG2_EXT else in_path.with_suffix(".dec")
        return decrypt_from_cg2(in_path, base, pwd, verify_only=False, progress_cb=progress_cb)
    raise ValueError("Unknown file format and legacy support disabled")

__all__ = [
    "encrypt", "decrypt", "get_cipher",
    "SecurityProfile", "LOG_PATH",
]
