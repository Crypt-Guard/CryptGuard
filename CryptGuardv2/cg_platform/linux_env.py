"""
Linux-specific helpers for diagnosing Qt platform plugin issues.
"""

from __future__ import annotations


def explain_qpa_failure() -> None:
    """Print guidance when the Qt platform plugin fails to load on Linux."""
    print(
        "Erro ao iniciar Qt no Linux.\n"
        "- Verifique se os pacotes do sistema do Qt estão instalados (xcb/wayland).\n"
        "- Em Ubuntu/Zorin, instale por exemplo:\n"
        "  sudo apt install -y libxcb1 libxkbcommon-x11-0 libxcb-render0 libxcb-shape0 "
        "libxcb-xfixes0 libxcb-cursor0 libxrender1 libxi6 libxcomposite1 libxcursor1 "
        "libxrandr2 libxdamage1 libglib2.0-0 libdbus-1-3 libx11-xcb1\n"
        "  (dependências do plugin xcb e bibliotecas relacionadas)\n"
        "Se estiver em Wayland, experimente QT_QPA_PLATFORM=wayland;xcb\n"
    )


def harden_process_best_effort() -> None:
    """Restrict core dumps and mark the process as non-dumpable on Linux."""
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass

    try:
        import ctypes

        libc = ctypes.CDLL(None)
        PR_SET_DUMPABLE = 4
        libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    except Exception:
        pass
