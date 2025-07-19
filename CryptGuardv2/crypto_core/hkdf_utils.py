"""
hkdf_utils.py  –  única fonte de verdade para derivar
(enc_key, hmac_key) a partir da chave mestra Argon2id.

• Usa HKDF‑SHA256 com 64 bytes de saída → 32 B enc_key || 32 B hmac_key
• Recebe explicitamente o mesmo `salt` de 16 B já usado no Argon2  (↑ robustez)
• `info` muda conforme o backend para manter compatibilidade (PFA‑keys/CGv2‑keys)
"""
from __future__ import annotations
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes    import SHA256
from .secure_bytes import SecureBytes

def derive_keys(master: SecureBytes, *, info: bytes, salt: bytes) -> tuple[bytes, bytes]:
    k = HKDF(algorithm=SHA256(), length=64, salt=salt, info=info).derive(master.to_bytes())
    return k[:32], k[32:]          # enc_key, hmac_key
