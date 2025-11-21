from __future__ import annotations

def harden_process_best_effort(logger=None):
    """
    Best-effort: desabilita core dumps e marca processo como não-dumpável.
    Não lança exceção se falhar; apenas loga.
    """
    import sys
    import ctypes

    try:
        import resource
    except Exception:
        resource = None

    def _log(level: str, msg: str) -> None:
        if logger is not None:
            getattr(logger, level)(msg)
        else:
            print(f"[{level.upper()}] {msg}", file=sys.stderr)

    try:
        if resource:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            _log("info", "Process hardening: RLIMIT_CORE=0")
    except Exception as e:  # pragma: no cover - best effort
        _log("warning", f"Process hardening: RLIMIT_CORE set failed: {e}")

    try:
        libc = ctypes.CDLL(None)
        PR_SET_DUMPABLE = 4
        if libc.prctl(PR_SET_DUMPABLE, 0) != 0:
            _log("warning", "Process hardening: prctl(PR_SET_DUMPABLE,0) returned non-zero")
        else:
            _log("info", "Process hardening: PR_SET_DUMPABLE=0")
    except Exception as e:  # pragma: no cover - best effort
        _log("warning", f"Process hardening: prctl failed: {e}")


__all__ = ["harden_process_best_effort"]
