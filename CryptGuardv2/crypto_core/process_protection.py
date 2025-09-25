"""
process_protection.py

Harden opcional do processo em Windows:

• Ativa DEP permanente
• Suprime caixas de erro (não controla a política global de dumps)
• Tenta detectar debugger (CheckRemoteDebuggerPresent)
"""

from __future__ import annotations

import ctypes
import platform

from .log_utils import log_best_effort
from .security_warning import warn


def _enable_dep():
    try:
        k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        # 0x1 = PROCESS_DEP_ENABLE  (docs: SetProcessDEPPolicy)
        ok = k32.SetProcessDEPPolicy(1)
        if not ok:
            warn("DEP não habilitado (política do sistema pode impedir).", sev="LOW")
        else:
            try:
                getpol = k32.GetSystemDEPPolicy
                state = getpol()
                warn(f"DEP enabled; system policy={state}", sev="LOW")
            except Exception as exc:
                log_best_effort(__name__, exc)
    except Exception as e:
        warn(f"Falha ao ativar DEP: {e}", sev="LOW")


def _disable_core_dumps():
    try:
        # SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
        SEM_FLAGS = 0x0001 | 0x0002 | 0x8000
        ctypes.windll.kernel32.SetErrorMode(SEM_FLAGS)  # type: ignore[attr-defined]
    except Exception as exc:
        log_best_effort(__name__, exc)  # nosec B110 — best-effort, sem impacto de segurança


def _check_debugger():
    try:
        dbg_present = ctypes.c_int(0)
        k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        k32.CheckRemoteDebuggerPresent(k32.GetCurrentProcess(), ctypes.byref(dbg_present))
        if dbg_present.value:
            warn("Debugger detectado! Hardening pode não ser efetivo.", sev="HIGH")
    except Exception as exc:
        log_best_effort(__name__, exc)  # nosec B110 — best-effort, sem impacto de segurança


def enable_process_hardening():
    if platform.system() != "Windows":
        warn("ProcessProtection: sistema não é Windows – ignorado.", sev="LOW")
        return
    _enable_dep()
    _disable_core_dumps()
    _check_debugger()
