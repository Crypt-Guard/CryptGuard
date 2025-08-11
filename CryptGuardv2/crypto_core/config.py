"""
Constantes e parâmetros (pode ser calibrado durante a execução).
"""
from __future__ import annotations
from enum import Enum, auto
import os, json
from pathlib import Path
from .paths import LOG_PATH, BASE_DIR  # Import from paths
from .argon_utils import calibrate_kdf
from .process_protection import enable_process_hardening as _apply_full_hardening

# ───── perfis de segurança ──────────────────────────────────────────────
class SecurityProfile(Enum):
    FAST     = auto()
    BALANCED = auto()
    SECURE   = auto()

ALGORITHMS = {
    "AES-GCM": {
        "module": "file_crypto_aes_gcm",
        "encrypt": "encrypt_file",
        "decrypt": "decrypt_file",
        "nonce": 16,
    },
    "ChaCha20-Poly1305": {
        "module": "file_crypto_chacha",
        "encrypt": "encrypt_file",
        "decrypt": "decrypt_file",
        "nonce": 12,
    },
    "XChaCha20-Poly1305": {
        "module": "file_crypto_xchacha",
        "encrypt": "encrypt_file",
        "decrypt": "decrypt_file",
        "stream": False,       # streaming usará outro módulo se criar depois
    },
}

# Custos Argon2 pré‑calibrados (serão ajustados se não existir cache)
ARGON_PRESETS = {
    SecurityProfile.FAST:     {"time": 2, "mem":  64 * 1024, "par": 2},
    SecurityProfile.BALANCED: {"time": 4, "mem":  128 * 1024, "par": 4},
    SecurityProfile.SECURE:   {"time": 8, "mem":  256 * 1024, "par": 4},
}

# Para compatibilidade com código existente
ARGON_PARAMS = {
    SecurityProfile.FAST:     dict(time_cost=ARGON_PRESETS[SecurityProfile.FAST]["time"], 
                                   memory_cost=ARGON_PRESETS[SecurityProfile.FAST]["mem"],  
                                   parallelism=ARGON_PRESETS[SecurityProfile.FAST]["par"]),
    SecurityProfile.BALANCED: dict(time_cost=ARGON_PRESETS[SecurityProfile.BALANCED]["time"], 
                                   memory_cost=ARGON_PRESETS[SecurityProfile.BALANCED]["mem"], 
                                   parallelism=ARGON_PRESETS[SecurityProfile.BALANCED]["par"]),
    SecurityProfile.SECURE:   dict(time_cost=ARGON_PRESETS[SecurityProfile.SECURE]["time"], 
                                   memory_cost=ARGON_PRESETS[SecurityProfile.SECURE]["mem"], 
                                   parallelism=ARGON_PRESETS[SecurityProfile.SECURE]["par"]),
}

META_ARGON_PARAMS = dict(time_cost=2, memory_cost=32*1024, parallelism=2)
DEFAULT_ARGON_PARAMS = ARGON_PARAMS[SecurityProfile.BALANCED]

STREAMING_THRESHOLD       = 100 * 1024 * 1024
CHUNK_SIZE                = 8   * 1024 * 1024
SINGLE_SHOT_SUBCHUNK_SIZE = 1   * 1024 * 1024

USE_RS          = True
RS_PARITY_BYTES = 32
SIGN_METADATA   = True

# ───── extensões / mágica de header ─────────────────────────────────────
MAGIC          = b"CGv2"       # nova versão do formato
CG2_EXT        = ".cg2"        # NOVO: formato único CG2
META_SALT_SIZE = 16

# ───── caminhos de app e calibração ─────────────────────────────────────
APP_DIR = BASE_DIR
LOG_PATH  = APP_DIR / "cryptguard.log"
CALIB_PATH = APP_DIR / "argon_calib.json"
APP_DIR.mkdir(exist_ok=True)

# ───── calibração automática (primeira execução) ───────────────────────
if not CALIB_PATH.exists():
    presets = calibrate_kdf()
    # If calibrate_kdf returns a flat dict, wrap it for all profiles
    if all(k in presets for k in ("time_cost", "memory_cost", "parallelism")):
        # Use the same calibration for all profiles
        mapped = {
            "FAST":     {"time": presets["time_cost"], "mem": presets["memory_cost"], "par": presets["parallelism"]},
            "BALANCED": {"time": presets["time_cost"], "mem": presets["memory_cost"], "par": presets["parallelism"]},
            "SECURE":   {"time": presets["time_cost"], "mem": presets["memory_cost"], "par": presets["parallelism"]},
        }
        presets = mapped
    CALIB_PATH.write_text(json.dumps(presets, indent=2))
    ARGON_PRESETS.update({
        SecurityProfile.FAST:     presets["FAST"],
        SecurityProfile.BALANCED: presets["BALANCED"],
        SecurityProfile.SECURE:   presets["SECURE"],
    })
    # Atualizar os parâmetros CG2s também
    for profile in SecurityProfile:
        profile_name = profile.name
        ARGON_PARAMS[profile] = dict(
            time_cost=ARGON_PRESETS[profile]["time"],
            memory_cost=ARGON_PRESETS[profile]["mem"],
            parallelism=ARGON_PRESETS[profile]["par"]
        )
else:
    try:
        presets = json.loads(CALIB_PATH.read_text())
        # If the loaded presets is a flat dict, wrap it for all profiles
        if all(k in presets for k in ("time_cost", "memory_cost", "parallelism")):
            mapped = {
                "FAST":     {"time": presets["time_cost"], "mem": presets["memory_cost"], "par": presets["parallelism"]},
                "BALANCED": {"time": presets["time_cost"], "mem": presets["memory_cost"], "par": presets["parallelism"]},
                "SECURE":   {"time": presets["time_cost"], "mem": presets["memory_cost"], "par": presets["parallelism"]},
            }
            presets = mapped
        for prof, cfg in presets.items():
            ARGON_PRESETS[SecurityProfile[prof]] = cfg
            # Atualizar os parâmetros CG2s também
            ARGON_PARAMS[SecurityProfile[prof]] = dict(
                time_cost=cfg["time"],
                memory_cost=cfg["mem"],
                parallelism=cfg["par"]
            )
    except Exception:  # noqa: BLE001
        pass

# ───── parâmetros de expiração (NOVOS) ──────────────────────────────────
# 0 = arquivos sem validade; altere conforme a política da aplicação.
DEFAULT_EXPIRATION_DAYS = 0        # dias
MAX_CLOCK_SKEW_SEC      = 31_536_000      # tolerância de relógio (1 ano)

# ───── proteção extra de processo (opcional) ───────────────────────────
def enable_process_hardening():
    """Habilita proteções de processo quando possível."""
    _apply_full_hardening()
    
    # Exemplo de hardening básico
    if hasattr(os, 'setpriority'):
        try:
            os.setpriority(os.PRIO_PROCESS, 0, 10)  # Baixa prioridade
        except Exception:
            pass
    
    # Outras proteções podem ser adicionadas aqui
    pass
    
    # Outras proteções podem ser adicionadas aqui
    pass

# Re-export for compatibility
__all__ = [
    "SecurityProfile", "ARGON_PARAMS", "READ_LEGACY_FORMATS", 
    "STREAMING_THRESHOLD", "CG2_EXT", "enable_process_hardening",
    "LOG_PATH", "BASE_DIR"  # Add these to exports
]

# Unified encrypted file extension for CG2 containers
ENC_EXT = ".cg2"
