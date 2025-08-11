"""Key derivation functions with dict parameter support for CG2 format."""
from __future__ import annotations

from argon2.low_level import hash_secret_raw, Type
from .secure_bytes   import SecureBytes
from .key_obfuscator import KeyObfuscator

# Default meta parameters (caller must pass a proper random salt)
META_ARGON_PARAMS = {
    "name": "argon2id",
    "time_cost": 2,
    "memory_cost": 512,
    "parallelism": 2,
}

def _sanitize_params(params: dict | None) -> dict:
    if not params:
        return {"time_cost": 2, "memory_cost": 512, "parallelism": 2}
    # accept dicts or objects with attributes
    get = lambda k, d: (getattr(params, k, None) if not isinstance(params, dict) else params.get(k, d))
    p = {
        "time_cost": int(get("time_cost", 2)),
        "memory_cost": int(get("memory_cost", 512)),
        "parallelism": int(get("parallelism", 2)),
    }
    # clamp values
    p["time_cost"] = max(1, min(p["time_cost"], 64))
    p["memory_cost"] = max(8, min(p["memory_cost"], 1024*1024))  # MiB
    p["parallelism"] = max(1, min(p["parallelism"], 32))
    return p

def _coerce_salt(salt_or_params) -> bytes:
    """
    Accepts:
      - bytes salt
      - dict/object with 'salt' as hex string or bytes
    """
    import binascii
    if isinstance(salt_or_params, (bytes, bytearray)):
        if len(salt_or_params) < 16:
            raise ValueError("salt must be >=16 bytes")
        return bytes(salt_or_params)
    # dict or object with .salt
    if hasattr(salt_or_params, "salt"):
        s = getattr(salt_or_params, "salt")
    elif isinstance(salt_or_params, dict):
        s = salt_or_params.get("salt")
    else:
        raise TypeError("salt_or_params must be bytes or a mapping/object with 'salt'")
    if isinstance(s, (bytes, bytearray)):
        b = bytes(s)
    elif isinstance(s, str):
        try:
            b = binascii.unhexlify(s.encode().replace(b" ", b""))
        except binascii.Error as e:
            raise ValueError("salt string must be hex-encoded") from e
    else:
        raise TypeError("unsupported salt type")
    if len(b) < 16:
        raise ValueError("salt must be >=16 bytes")
    return b

def generate_key_from_password(pswd_sb: SecureBytes, salt: bytes, params: dict | None) -> tuple[KeyObfuscator, dict]:
    """
    Derives a 32-byte master key using Argon2id and wraps it in KeyObfuscator.
    Returns: (KeyObfuscator(master_key), params_used_dict)
    """
    if not isinstance(pswd_sb, SecureBytes):
        if isinstance(pswd_sb, (bytes, bytearray)):
            pswd_sb = SecureBytes(bytes(pswd_sb))
        else:
            raise TypeError("pswd_sb must be SecureBytes or bytes")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
        raise ValueError("salt must be >=16 bytes")
    p = _sanitize_params(params)
    raw = hash_secret_raw(
        secret=pswd_sb.to_bytes(),
        salt=bytes(salt),
        time_cost=p["time_cost"],
        memory_cost=p["memory_cost"],
        parallelism=p["parallelism"],
        hash_len=32,
        type=Type.ID,
    )
    mk_sb = SecureBytes(raw)
    obf = KeyObfuscator(mk_sb)
    mk_sb.clear()
    return obf, p

def derive_key(password: bytes | str | SecureBytes, salt_or_params) -> bytes:
    """
    Backward-compatible wrapper expected by cg2_ops.
    - Accepts password as str/bytes/SecureBytes.
    - Accepts salt_or_params as bytes or dict/object with fields (salt,time_cost,memory_cost,parallelism).
    - Returns raw 32-byte key (bytes).
    """
    if isinstance(password, str):
        password = password.encode()
    if not isinstance(password, SecureBytes):
        password = SecureBytes(bytes(password))
    salt = _coerce_salt(salt_or_params)
    # optional params
    params = None
    if not isinstance(salt_or_params, (bytes, bytearray)):
        maybe = {}
        for k in ("time_cost", "memory_cost", "parallelism"):
            if isinstance(salt_or_params, dict) and k in salt_or_params:
                maybe[k] = salt_or_params[k]
            elif hasattr(salt_or_params, k):
                maybe[k] = getattr(salt_or_params, k)
        params = maybe or None
    obf, _p = generate_key_from_password(password, salt, params)
    try:
        return obf.deobfuscate().to_bytes()
    finally:
        try: obf.clear()
        except Exception: pass

def derive_meta_key(pswd_sb: SecureBytes, salt: bytes):
    obf, _ = generate_key_from_password(pswd_sb, salt, META_ARGON_PARAMS)
    return obf.deobfuscate()
