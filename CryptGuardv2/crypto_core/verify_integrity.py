"""
Verifica a integridade (HMAC) *sem* descriptografar o conteúdo.
Bloqueia imediatamente se os metadados indicarem que o arquivo expirou.
"""
from __future__ import annotations

import hmac, hashlib
from pathlib import Path

from .secure_bytes   import SecureBytes
from .key_obfuscator import TimedExposure
from .kdf            import derive_key
from .metadata       import decrypt_meta_json
from .config         import MAGIC, ENC_EXT, META_EXT, SecurityProfile
from .utils          import unpack_enc_zip, check_expiry, ExpiredFileError
from .hkdf_utils     import derive_keys

# Tag do algoritmo (4 bytes) na cabeça do arquivo .enc
ALG_TAGS = {
    b"ACTR": b"CGv2-keys",    # AES-CTR
    b"AESG": b"PFA-keys",     # AES-GCM
    b"CH20": b"PFA-keys",     # ChaCha20-Poly1305 single-shot
    b"CHS3": b"PFA-keys",     # ChaCha20-Poly1305 streaming
    b"XC20": b"PFA-keys",     # XChaCha20-Poly1305 single-shot
    b"XCS3": b"PFA-keys",     # XChaCha20-Poly1305 streaming
}

def verify_integrity(
    enc_path: str | Path,
    password: str,
    profile_hint: SecurityProfile = SecurityProfile.BALANCED,
) -> bool:
    """
    Retorna **True** se o HMAC bate.  
    Levanta `ExpiredFileError` se o arquivo estiver vencido.
    """
    enc_path = Path(enc_path)
    pwd_sb   = SecureBytes(password.encode())

    # Caso o usuário passe um ZIP (pack_enc_zip)
    if enc_path.suffix.lower() == ".zip":
        src, _tmp = unpack_enc_zip(enc_path)
    else:
        src = enc_path

    # ─── lê cabeçalho mínimo ───────────────────────────────────────────
    with src.open("rb") as fin:
        salt      = fin.read(16)
        magic     = fin.read(4)
        tag_alg   = fin.read(4)
        if magic != MAGIC:
            pwd_sb.clear()
            raise ValueError("Formato inválido ou arquivo corrompido.")

    # ─── decifra metadados ─────────────────────────────────────────────
    meta_path = src.with_suffix(src.suffix + META_EXT)
    meta = decrypt_meta_json(meta_path, pwd_sb)

    # ─── verifica expiração (lança se vencido) ─────────────────────────-
    check_expiry(meta)

    if not meta.get("hmac"):
        pwd_sb.clear()
        return False  # sem HMAC para validar

    # ─── deriva chave HMAC exatamente como no encrypt_* ────────────────
    info = ALG_TAGS.get(tag_alg, b"CGv2-keys")
    master_obf = derive_key(pwd_sb, salt, profile_hint)
    with TimedExposure(master_obf) as master:
        _, hmac_key = derive_keys(master, info=info, salt=salt)

    # ─── calcula e compara digest ──────────────────────────────────────
    calc = hmac.new(hmac_key, src.read_bytes(), hashlib.sha256).hexdigest()
    master_obf.clear(); pwd_sb.clear()
    return hmac.compare_digest(calc, meta["hmac"])
