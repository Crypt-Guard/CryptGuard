"""
Metadata JSON duplamente protegido:
• Salt (16)    – derivação de chave leve (Argon2id reduzido)
• Nonce (12)   – ChaCha20-Poly1305
• CipherText   – JSON(minificado) + tag
"""
import secrets, json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from .secure_bytes import SecureBytes
from .kdf          import derive_meta_key
from .utils        import write_atomic_secure
from .config       import META_SALT_SIZE

def _pack(obj: dict) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()

def _unpack(b: bytes) -> dict:
    return json.loads(b.decode())

def encrypt_meta_json(meta_path: Path, meta: dict, pwd_sb: SecureBytes) -> None:
    salt  = secrets.token_bytes(META_SALT_SIZE)
    key   = derive_meta_key(pwd_sb, salt)     # -> SecureBytes
    nonce = secrets.token_bytes(12)
    cipher = ChaCha20Poly1305(key.to_bytes())
    blob = salt + nonce + cipher.encrypt(nonce, _pack(meta), None)
    write_atomic_secure(meta_path, blob)
    key.clear()

def decrypt_meta_json(meta_path: Path, pwd_sb: SecureBytes) -> dict:
    blob = Path(meta_path).read_bytes()
    salt, nonce, ct = blob[:META_SALT_SIZE], blob[META_SALT_SIZE:META_SALT_SIZE+12], blob[META_SALT_SIZE+12:]
    key = derive_meta_key(pwd_sb, salt)
    data = ChaCha20Poly1305(key.to_bytes()).decrypt(nonce, ct, None)
    key.clear()
    return _unpack(data)
