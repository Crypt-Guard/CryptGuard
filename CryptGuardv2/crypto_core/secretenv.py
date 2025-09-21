from __future__ import annotations

import functools
import inspect


def no_str_secrets(*secret_param_names: str):
    """
    Decorator that rejects str in marked secret parameters.
    Usage: @no_str_secrets("password", "keyfile_bytes")
    """

    def deco(fn):
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            bound = sig.bind_partial(*args, **kwargs)
            for p in secret_param_names:
                if p in bound.arguments:
                    val = bound.arguments[p]
                    if isinstance(val, str):
                        raise TypeError(f"Secret '{p}' must be bytes-like, not str")
                    if val is not None:
                        try:
                            # aceita bytes-like: bytes, bytearray, memoryview
                            ln = len(val)  # type: ignore[arg-type]
                            if ln == 0:
                                raise ValueError(f"Secret '{p}' cannot be empty")
                        except TypeError:
                            # objeto não "sized" — sem checagem de tamanho
                            pass
            return fn(*args, **kwargs)

        return wrapper

    return deco

