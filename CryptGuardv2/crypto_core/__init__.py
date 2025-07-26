"""crypto_core/__init__.py – bootstrap compacto v3 (pós‑refatoração)

Responsabilidades principais
────────────────────────────
1. Verificar dependências mínimas e inicializar logging/banco de dados.
2. Processar flags globais de CLI (**--calibrate-kdf**, **--harden**).
3. Carregar (ou autodetectar) calibração Argon2id.
4. Expor a API pública simplificada baseada em fábricas:

   • `encrypt(path, password, algo="AESG", **kw)`
   • `decrypt(path, password, **kw)`
   • `get_cipher(tag, streaming=None)`
   • constantes `SecurityProfile`, `LOG_PATH`

Todo o roteamento de algoritmos agora é delegado a `factories.py`.
"""
from __future__ import annotations

import sys, argparse
from importlib import util
from pathlib import Path

from .logger             import logger, LOG_PATH  # inicializa logger
from .config             import enable_process_hardening, SecurityProfile, ARGON_PARAMS
from .argon_utils        import load_calibrated_params, calibrate_kdf
from .factories          import encrypt, decrypt, get_cipher  # API de alto nível

# ─── dependências mínimas ────────────────────────────────────────────────
_REQ = {"psutil", "argon2", "reedsolo", "PySide6", "cryptography"}
_missing = [pkg for pkg in _REQ if util.find_spec(pkg) is None]
if _missing:
    logger.critical(f"Dependências ausentes: {_missing}. Instale e tente novamente.")
    sys.exit(1)

# ─── flags globais (--calibrate-kdf, --harden) ───────────────────────────
_ap = argparse.ArgumentParser(add_help=False)
_ap.add_argument("--calibrate-kdf", action="store_true",
                help="calibra Argon2id para ~0,5 s")
_ap.add_argument("--harden", action="store_true",
                help="ativa proteções de processo (mlock, anti‑debug)")
_args, _ = _ap.parse_known_args()

if _args.calibrate_kdf:
    calibrate_kdf()
    print("Calibração Argon2 concluída.")
    sys.exit(0)
if _args.harden:
    enable_process_hardening()

# ─── calibração Argon2 (aplicada aos perfis) ─────────────────────────────
_calib = load_calibrated_params()
if _calib and isinstance(_calib, dict):
    # sobrescreve valores padrão
    for prof in ARGON_PARAMS:
        ARGON_PARAMS[prof].update(_calib)
        if prof == SecurityProfile.SECURE:
            ARGON_PARAMS[prof]["time_cost"] *= 2
            ARGON_PARAMS[prof]["memory_cost"] *= 2

__all__ = [
    # API pública reexportada da fábrica
    "encrypt", "decrypt", "get_cipher",
    # Configuração / enums úteis
    "SecurityProfile", "LOG_PATH",
]
