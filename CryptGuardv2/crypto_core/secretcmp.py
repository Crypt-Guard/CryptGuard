from __future__ import annotations

import hmac
import secrets
import time

from .log_utils import log_best_effort


def consteq(a, b) -> bool:
    # pequenos (e.g., 32B): conversão a bytes não causa pressão de heap
    try:
        return hmac.compare_digest(bytes(a), bytes(b))
    except Exception as exc:
        log_best_effort(__name__, exc)
        return False


class EphemeralToken:
    def __init__(self, ttl_s: int = 10):
        self.v = bytearray(secrets.token_bytes(32))
        self.exp = time.time() + ttl_s

    def verify(self, other: bytes) -> bool:
        return time.time() <= self.exp and consteq(self.v, other)

    def wipe(self):
        try:
            for i in range(len(self.v)):
                self.v[i] = 0
            self.v.clear()
        except Exception as exc:
            log_best_effort(__name__, exc)
