from __future__ import annotations

import hmac
import secrets
import time


def consteq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


class EphemeralToken:
    def __init__(self, ttl_s: int = 10):
        self.v = secrets.token_bytes(32)
        self.exp = time.time() + ttl_s

    def verify(self, other: bytes) -> bool:
        return time.time() <= self.exp and consteq(self.v, other)

    def wipe(self):
        try:
            self.v = b"\x00" * len(self.v)
        except Exception:
            pass

