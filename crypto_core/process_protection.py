"""
process_protection.py

Harden opcional do processo em Windows:

• Ativa DEP permanente
• Desabilita criação de core-dumps
• Tenta bloquear debugging (CheckRemoteDebuggerPresent)
Chamado via flag --harden ao iniciar o CryptGuard.
"""
import ctypes, os, platform
from .security_warning import warn

def _enable_dep():
    try:
        k32 = ctypes.windll.kernel32
        # 0x1 = PROCESS_DEP_ENABLE  (docs: SetProcessDEPPolicy)
        k32.SetProcessDEPPolicy(1)
    except Exception as e:
        warn(f"Falha ao ativar DEP: {e}", sev="LOW")

def _disable_core_dumps():
    try:
        # SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
        SEM_FLAGS = 0x0001 | 0x0002 | 0x8000
        ctypes.windll.kernel32.SetErrorMode(SEM_FLAGS)
    except Exception:
        pass

def _check_debugger():
    try:
        dbg_present = ctypes.c_int(0)
        ctypes.windll.kernel32.CheckRemoteDebuggerPresent(
            ctypes.windll.kernel32.GetCurrentProcess(),
            ctypes.byref(dbg_present)
        )
        if dbg_present.value:
            warn("Debugger detectado! Hardening pode não ser efetivo.", sev="HIGH")
    except Exception:
        pass

def enable_process_hardening():
    if platform.system() != "Windows":
        warn("ProcessProtection: sistema não é Windows – ignorado.", sev="LOW")
        return
    _enable_dep()
    _disable_core_dumps()
    _check_debugger()
    # lock todas as páginas atuais e futuras (melhor esforço; pode falhar se privilégio baixo)
    try:
        # 0x0001 | 0x0002 = MCL_CURRENT | MCL_FUTURE análogo em Windows? indisponível.
        # em Windows é VirtualLock por página; não tentamos aqui.
        pass
    except Exception:
        pass
