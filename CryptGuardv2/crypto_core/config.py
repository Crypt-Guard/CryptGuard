"""
Parâmetros centrais do CryptGuard v3.0 (writer único: v5 SecretStream).
Inclui perfis de KDF (com calibração/override via arquivo) e caminhos.
"""

from __future__ import annotations

import json
import os
from enum import Enum, auto

from .argon_utils import calibrate_kdf
from .log_utils import log_best_effort
from .paths import BASE_DIR, LOG_PATH
from .process_protection import enable_process_hardening as _apply_full_hardening


# ───── perfis de segurança ──────────────────────────────────────────────
class SecurityProfile(Enum):
    FAST = auto()
    BALANCED = auto()
    SECURE = auto()


# Writer único (v5):
WRITE_FORMAT = "v5-secretstream"

# Custos Argon2 pré-calibrados (serão ajustados se existir cache)
ARGON_PRESETS = {
    SecurityProfile.FAST: {"time": 2, "mem": 64 * 1024, "par": 2},
    SecurityProfile.BALANCED: {"time": 4, "mem": 128 * 1024, "par": 4},
    SecurityProfile.SECURE: {"time": 8, "mem": 256 * 1024, "par": 4},
}

ARGON_PARAMS = {
    SecurityProfile.FAST: {
        "time_cost": ARGON_PRESETS[SecurityProfile.FAST]["time"],
        "memory_cost": ARGON_PRESETS[SecurityProfile.FAST]["mem"],
        "parallelism": ARGON_PRESETS[SecurityProfile.FAST]["par"],
    },
    SecurityProfile.BALANCED: {
        "time_cost": ARGON_PRESETS[SecurityProfile.BALANCED]["time"],
        "memory_cost": ARGON_PRESETS[SecurityProfile.BALANCED]["mem"],
        "parallelism": ARGON_PRESETS[SecurityProfile.BALANCED]["par"],
    },
    SecurityProfile.SECURE: {
        "time_cost": ARGON_PRESETS[SecurityProfile.SECURE]["time"],
        "memory_cost": ARGON_PRESETS[SecurityProfile.SECURE]["mem"],
        "parallelism": ARGON_PRESETS[SecurityProfile.SECURE]["par"],
    },
}

META_ARGON_PARAMS = {"time_cost": 2, "memory_cost": 32 * 1024, "parallelism": 2}
DEFAULT_ARGON_PARAMS = ARGON_PARAMS[SecurityProfile.BALANCED]

STREAMING_THRESHOLD = 100 * 1024 * 1024
CHUNK_SIZE = 8 * 1024 * 1024

# Parâmetros legados foram removidos daqui para evitar confusão.
# Caso haja leitura v1–v4 em crypto_core/legacy, deixe os valores
# específicos **apenas** lá.

CG2_EXT = ".cg2"
META_SALT_SIZE = 16

# Compat legada governada por flag (default: aceita formatos legados)
READ_LEGACY_FORMATS = True

# ───── caminhos de app e calibração ─────────────────────────────────────
# Centralizamos em BASE_DIR (crypto_core.paths) e não sobrescrevemos LOG_PATH aqui.
BASE_DIR.mkdir(parents=True, exist_ok=True)
CALIB_PATH = BASE_DIR / "argon_calib.json"
SETTINGS_PATH = BASE_DIR / "settings.json"


# ───── calibração automática (primeira execução) ───────────────────────
def _map_flat_presets(p: dict) -> dict:
    # converte {"time_cost":..,"memory_cost":..,"parallelism":..} para FAST/BALANCED/SECURE
    return {
        "FAST": {
            "time": p["time_cost"],
            "mem": p["memory_cost"],
            "par": p["parallelism"],
        },
        "BALANCED": {
            "time": p["time_cost"],
            "mem": p["memory_cost"],
            "par": p["parallelism"],
        },
        "SECURE": {
            "time": p["time_cost"],
            "mem": p["memory_cost"],
            "par": p["parallelism"],
        },
    }


if not CALIB_PATH.exists():
    presets = calibrate_kdf()
    if all(k in presets for k in ("time_cost", "memory_cost", "parallelism")):
        presets = _map_flat_presets(presets)
    CALIB_PATH.write_text(json.dumps(presets, indent=2), encoding="utf-8")
else:
    try:
        presets = json.loads(CALIB_PATH.read_text(encoding="utf-8"))
    except Exception:
        presets = {}

# aplica presets (se válidos)
try:
    if presets and all(k in presets for k in ("FAST", "BALANCED", "SECURE")):
        for prof_name, cfg in presets.items():
            prof = SecurityProfile[prof_name]
            ARGON_PRESETS[prof] = cfg
            ARGON_PARAMS[prof] = {
                "time_cost": cfg["time"],
                "memory_cost": cfg["mem"],
                "parallelism": cfg["par"],
            }
except Exception:
    # melhor-esforço apenas
    pass

# ───── parâmetros de expiração (opcionais) ──────────────────────────────
DEFAULT_EXPIRATION_DAYS = 0
MAX_CLOCK_SKEW_SEC = 31_536_000  # 365d


# ───── higiene de arquivos (secure delete e temporários) ─────────────────
HYGIENE_TEMP_DIR = BASE_DIR / "temp"
HYGIENE_DEFAULT_SETTINGS = {
    "delete_original_after_encrypt": False,  # Opt-in para segurança
    "clean_temp_on_startup": True,
    "clean_temp_on_shutdown": True,
    "secure_delete_passes": 3,  # 1-7 passes
}



# ───── proteção extra de processo (opcional) ───────────────────────────
def enable_process_hardening():
    """Habilita proteções de processo quando possível (best effort)."""
    _apply_full_hardening()
    if hasattr(os, "setpriority"):
        try:
            os.setpriority(os.PRIO_PROCESS, 0, 10)  # baixa prioridade
        except Exception as exc:
            log_best_effort(__name__, exc)  # nosec B110 — best-effort, sem impacto de segurança


__all__ = [
    "SecurityProfile",
    "ARGON_PRESETS",
    "ARGON_PARAMS",
    "DEFAULT_ARGON_PARAMS",
    "READ_LEGACY_FORMATS",
    "STREAMING_THRESHOLD",
    "CG2_EXT",
    "enable_process_hardening",
    "LOG_PATH",
    "BASE_DIR",
    "CALIB_PATH",
    "WRITE_FORMAT",
    "SETTINGS_PATH",
    "HYGIENE_TEMP_DIR",
    "HYGIENE_DEFAULT_SETTINGS",
]
