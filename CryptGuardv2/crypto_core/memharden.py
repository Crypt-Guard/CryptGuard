from __future__ import annotations

import os
import sys


def harden_process_best_effort():
    """Reduce memory leakage avenues: disable core dumps (POSIX), disable ptrace dumps,
    best-effort and non-fatal on failure. No effect on Windows without privileges.
    
    Em Linux/macOS:
    - RLIMIT_CORE=0: desabilita core dumps
    - prctl(PR_SET_DUMPABLE, 0): impede ptrace attachment
    
    Em Windows:
    - Sem privilégios elevados, nenhuma ação é realizada
    - Dumps são controlados por políticas do sistema e WER (Windows Error Reporting)
    
    Nota: algumas distribuições Linux podem ter coredumpctl/systemd que
    sobrescreve configurações de processo. Verificar políticas do sistema.
    """
    try:
        if sys.platform.startswith("linux") or sys.platform == "darwin":
            try:
                import resource  # type: ignore

                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            except Exception:
                pass
            try:
                import ctypes

                PR_SET_DUMPABLE = 4
                ctypes.CDLL(None).prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
            except Exception:
                pass
        elif os.name == "nt":
            # Nothing critical to do here without elevated privileges.
            pass
    except Exception:
        pass

