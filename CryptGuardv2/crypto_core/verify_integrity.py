from __future__ import annotations
import hmac, hashlib
from pathlib import Path
from .secure_bytes import SecureBytes
from .key_obfuscator import TimedExposure
from .kdf import derive_key
from .metadata import decrypt_meta_json
from .config import MAGIC, ENC_EXT, META_EXT, SecurityProfile
from .utils import unpack_enc_zip
from .file_crypto import _hkdf
from .hkdf_utils import derive_keys

def verify_integrity(enc_path: str | Path, password: str, profile_hint: SecurityProfile = SecurityProfile.BALANCED) -> bool:
    """
    Verifica integridade via HMAC sem decriptar. Retorna True se OK.
    """
    enc_path = Path(enc_path)
    pwd_sb = SecureBytes(password.encode())

    if enc_path.suffix.lower() == ".zip":
        src, _tmp = unpack_enc_zip(enc_path)
    else:
        src = enc_path

    with src.open("rb") as fin:
        salt = fin.read(16)
        magic = fin.read(4)
        tag_alg = fin.read(4)
        if magic != MAGIC:
            pwd_sb.clear()
            raise ValueError("Formato inválido.")

    meta_path = src.with_suffix(src.suffix + META_EXT)
    meta = decrypt_meta_json(meta_path, pwd_sb)

    if not meta.get("hmac"):
        pwd_sb.clear()
        return False  # Sem HMAC para verificar

    info = b"CGv2-keys" if tag_alg==b"ACTR" else b"PFA-keys"
    master_obf = derive_key(pwd_sb, salt, profile_hint)
    with TimedExposure(master_obf) as master:
        # derive exactly the same enc_key and hmac_key as encrypt/decrypt
        _, hmac_key = derive_keys(master, info=info, salt=salt)

    # compute HMAC using the exact key derived above
    calc = hmac.new(hmac_key, src.read_bytes(), hashlib.sha256).hexdigest()

    valid = hmac.compare_digest(calc, meta["hmac"])
    
    master_obf.clear()
    pwd_sb.clear()
    return valid