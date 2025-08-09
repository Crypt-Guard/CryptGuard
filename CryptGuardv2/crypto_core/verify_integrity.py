"""
Verifica a integridade (HMAC) *sem* descriptografar o conteúdo.
Bloqueia imediatamente se os metadados indicarem que o arquivo expirou.
"""
from __future__ import annotations

import hmac, hashlib
from pathlib import Path

from .fileformat     import is_cg2_file
from .cg2_ops        import decrypt_from_cg2
from .secure_bytes   import SecureBytes
from .key_obfuscator import TimedExposure
from .kdf            import derive_key
from .metadata       import decrypt_meta_json
from .config         import MAGIC, META_EXT, SecurityProfile, READ_LEGACY_FORMATS
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
    Retorna **True** se a verificação de integridade passou.
    Para CG2: usa AEAD tags. Para legado: usa HMAC.
    Levanta `ExpiredFileError` se o arquivo estiver vencido.
    """
    enc_path = Path(enc_path)
    pwd_bytes = password.encode()
    
    # Check if it's a CG2 file
    if is_cg2_file(enc_path):
        try:
            # For CG2, verification is done via AEAD tags
            return bool(decrypt_from_cg2(enc_path, "", pwd_bytes, verify_only=True))
        except Exception:
            return False
    
    # Legacy format verification
    if not READ_LEGACY_FORMATS:
        raise ValueError("Legacy format not supported")
        
    return _verify_legacy_integrity(enc_path, pwd_bytes, profile_hint)

def _verify_legacy_integrity(
    enc_path: Path,
    pwd_bytes: bytes,
    profile_hint: SecurityProfile,
) -> bool:
    """Legacy HMAC-based verification for .enc+.meta files."""
    pwd_sb = SecureBytes(pwd_bytes)

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
    h = hmac.new(hmac_key, digestmod=hashlib.sha256)
    with src.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    calc = h.hexdigest()
    master_obf.clear(); pwd_sb.clear()
    return hmac.compare_digest(calc, meta["hmac"])
