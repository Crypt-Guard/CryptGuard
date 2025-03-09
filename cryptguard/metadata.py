# metadata.py

import os
import json
import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from argon_utils import generate_key_from_password
from config import META_ARGON_PARAMS

from config import META_SALT_SIZE

def encrypt_meta_json(meta_path: str, meta_plain: dict, user_password: bytearray):
    """
    Encrypts meta_plain (a dict) into JSON and saves it in a .meta file:
    meta_salt, meta_nonce, meta_ciphertext.
    """
    meta_salt = secrets.token_bytes(META_SALT_SIZE)
    meta_key = generate_key_from_password(user_password, meta_salt, META_ARGON_PARAMS)
    cipher = ChaCha20Poly1305(bytes(meta_key))

    try:
        meta_nonce = secrets.token_bytes(12)
        meta_json_str = json.dumps(meta_plain, sort_keys=True)
        meta_cipher = cipher.encrypt(meta_nonce, meta_json_str.encode(), None)
        meta_dict = {
            "meta_salt": base64.b64encode(meta_salt).decode(),
            "meta_nonce": base64.b64encode(meta_nonce).decode(),
            "meta_ciphertext": base64.b64encode(meta_cipher).decode()
        }
        with open(meta_path, 'w') as f:
            json.dump(meta_dict, f)
    finally:
        for i in range(len(meta_key)):
            meta_key[i] = 0

def decrypt_meta_json(meta_path: str, user_password: bytearray):
    """
    Decrypts the content of the .meta file and returns a dictionary.
    Returns None if decryption fails or metadata is incomplete.
    """
    if not os.path.exists(meta_path):
        return None

    with open(meta_path, 'r') as f:
        meta_dict = json.load(f)

    try:
        meta_salt = base64.b64decode(meta_dict["meta_salt"])
        meta_nonce = base64.b64decode(meta_dict["meta_nonce"])
        meta_cipher = base64.b64decode(meta_dict["meta_ciphertext"])
    except Exception:
        return None

    meta_key = generate_key_from_password(user_password, meta_salt, META_ARGON_PARAMS)
    cipher = ChaCha20Poly1305(bytes(meta_key))
    try:
        meta_json_str = cipher.decrypt(meta_nonce, meta_cipher, None)
        meta = json.loads(meta_json_str.decode())
        if not isinstance(meta, dict):
            raise ValueError("Metadata is not a valid dictionary.")
        if not ("salt" in meta or "decoy_salt" in meta or "real_salt" in meta):
            raise ValueError("Salt field missing in metadata.")
        return meta
    except (InvalidTag, ValueError):
        return None
    finally:
        for i in range(len(meta_key)):
            meta_key[i] = 0
