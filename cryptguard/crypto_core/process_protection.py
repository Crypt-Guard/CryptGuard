"""
Process protection utilities for CryptGuard.
"""

import platform
import ctypes
import logging
import time
import threading
from typing import Optional, Callable

logger = logging.getLogger(__name__)

class ProcessProtection:
    """Apply simple anti-debugging protections."""

    def __init__(self):
        self.protected = False
        self.debugger_detected = False

    def apply_protections(self) -> None:
        if self.protected:
            return
        if platform.system() == "Windows":
            self._apply_windows_protections()
        elif platform.system() in ["Linux", "Darwin"]:
            self._apply_unix_protections()
        self.protected = True
        logger.info("Process protections applied")

    def _apply_windows_protections(self) -> None:
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            DEP_ENABLE = 0x00000001
            if hasattr(kernel32, "SetProcessDEPPolicy"):
                kernel32.SetProcessDEPPolicy(DEP_ENABLE)
            if kernel32.IsDebuggerPresent():
                self.debugger_detected = True
                logger.warning("Debugger detected")
            remote_present = ctypes.c_bool()
            if hasattr(kernel32, "CheckRemoteDebuggerPresent"):
                kernel32.CheckRemoteDebuggerPresent(
                    kernel32.GetCurrentProcess(), ctypes.byref(remote_present)
                )
                if remote_present.value:
                    self.debugger_detected = True
                    logger.warning("Remote debugger detected")
            if hasattr(kernel32, "SetDllDirectoryW"):
                kernel32.SetDllDirectoryW("")
        except Exception as e:
            logger.error("Windows protections failed: %s", e)

    def _apply_unix_protections(self) -> None:
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            if platform.system() == "Linux":
                try:
                    import ctypes.util
                    libc = ctypes.CDLL(ctypes.util.find_library("c"))
                    PTRACE_TRACEME = 0
                    result = libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
                    if result == -1:
                        self.debugger_detected = True
                        logger.warning("Debugger detected via ptrace")
                    else:
                        PTRACE_DETACH = 17
                        libc.ptrace(PTRACE_DETACH, 0, 0, 0)
                except Exception:
                    pass
        except Exception as e:
            logger.error("Unix protections failed: %s", e)

    def continuous_check(self, callback: Optional[Callable] = None) -> None:
        def check_loop():
            while True:
                time.sleep(30)
                prev = self.debugger_detected
                self._check_debugger()
                if self.debugger_detected and not prev:
                    logger.warning("Debugger attached during runtime")
                    if callback:
                        callback()
        thread = threading.Thread(target=check_loop, daemon=True)
        thread.start()

    def _check_debugger(self) -> None:
        if platform.system() == "Windows":
            try:
                kernel32 = ctypes.WinDLL("kernel32")
                if kernel32.IsDebuggerPresent():
                    self.debugger_detected = True
            except Exception:
                pass
        elif platform.system() == "Linux":
            try:
                with open("/proc/self/status", "r") as f:
                    for line in f:
                        if line.startswith("TracerPid:"):
                            if int(line.split()[1]) != 0:
                                self.debugger_detected = True
                            break
            except Exception:
                pass

process_protection = ProcessProtection()
