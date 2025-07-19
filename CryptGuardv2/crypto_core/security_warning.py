"""
Canal central de avisos de segurança.
"""
from enum import Enum
from .logger import logger

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

def warn(message: str, sev: "Severity | str" = Severity.MEDIUM):
    # aceita string ou Enum – converte se necessário
    if isinstance(sev, str):
        try:
            sev = Severity[sev.upper()]
        except KeyError:
            sev = Severity.MEDIUM  # fallback seguro
    logger.warning("SecurityWarning [%s] %s", sev.value, message)

def warn_critical(msg: str): warn(msg, Severity.CRITICAL)
