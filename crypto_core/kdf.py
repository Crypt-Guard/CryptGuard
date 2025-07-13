from __future__ import annotations
from .secure_bytes import SecureBytes
from .argon_utils  import generate_key_from_password
from .config       import SecurityProfile, ARGON_PARAMS, META_ARGON_PARAMS

def derive_key(pswd_sb:SecureBytes, salt:bytes, profile:SecurityProfile):
    obf,_ = generate_key_from_password(pswd_sb, salt, ARGON_PARAMS[profile])
    return obf          # KeyObfuscator

def derive_meta_key(pswd_sb:SecureBytes, salt:bytes):
    obf,_ = generate_key_from_password(pswd_sb, salt, META_ARGON_PARAMS)
    return obf.deobfuscate()
