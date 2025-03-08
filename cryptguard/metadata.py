# metadata.py

import os
import json
import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from argon_utils import generate_key_from_password, META_ARGON_PARAMS
from config import META_SALT_SIZE

def encrypt_meta_json(meta_path: str, meta_plain: dict, user_password: bytearray):
    """
    Cifra (meta_plain) em JSON, salvando no arquivo .meta:
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
    Decifra o conteúdo do arquivo .meta e retorna um dicionário.
    Retorna None se a descriptografia falhar ou se os metadados não estiverem completos.
    Após decifrar, valida se os campos essenciais estão presentes.
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
        # Validação básica dos metadados: verifica se pelo menos um campo de salt é encontrado.
        if not isinstance(meta, dict):
            raise ValueError("Metadados não são um dicionário válido.")
        if not ("salt" in meta or "falso_salt" in meta or "real_salt" in meta):
            raise ValueError("Campo de salt ausente nos metadados.")
        return meta
    except (InvalidTag, ValueError):
        return None
    finally:
        for i in range(len(meta_key)):
            meta_key[i] = 0
