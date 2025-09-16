from __future__ import annotations

import os
import sys


def harden_process_best_effort():
    """Reduce memory leakage avenues: disable core dumps, etc. Best-effort."""
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

