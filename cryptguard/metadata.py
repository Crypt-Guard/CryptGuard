# metadata.py
"""
Metadata encryption and decryption (.meta files) using ChaCha20Poly1305,
with Argon2id-based key derivation.

Agora com gravação atômica:
- Removemos a escrita intermediária do meta_dict diretamente no arquivo.
- Escrevemos apenas o outer_dict em um arquivo temporário e então renomeamos.
"""

import os
import json
import base64
import secrets

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from argon_utils import generate_key_from_password
from config import META_ARGON_PARAMS, META_SALT_SIZE

from typing import Optional, Dict, Any


def encrypt_meta_json(meta_path: str, meta_plain: dict,
                      user_password: bytearray) -> bool:
    """
    Encrypts a dict (meta_plain) into JSON and saves it in a .meta file.
    Using two layers of encryption (inner + outer) but now writing only the final result.

    Returns True on success, False on error.
    """

    # =========================
    # CAMADA 1 (INTERNAL META)
    # =========================

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
    finally:
        for i in range(len(meta_key)):
            meta_key[i] = 0

    # =========================
    # CAMADA 2 (EXTERNAL META)
    # =========================

    inner_meta_str = json.dumps(meta_dict)
    outer_salt = secrets.token_bytes(META_SALT_SIZE)
    outer_key = generate_key_from_password(user_password, outer_salt, META_ARGON_PARAMS)
    outer_cipher = ChaCha20Poly1305(bytes(outer_key))
    outer_nonce = secrets.token_bytes(12)
    try:
        outer_ciphertext = outer_cipher.encrypt(outer_nonce, inner_meta_str.encode(), None)
    finally:
        for i in range(len(outer_key)):
            outer_key[i] = 0

    outer_dict = {
        "outer_salt": base64.b64encode(outer_salt).decode(),
        "outer_nonce": base64.b64encode(outer_nonce).decode(),
        "outer_ciphertext": base64.b64encode(outer_ciphertext).decode()
    }

    # Gravacao atomica em arquivo temporario
    import tempfile
    import os

    tmp_path = meta_path + ".tmp"
    try:
        with open(tmp_path, 'w') as f:
            json.dump(outer_dict, f)
    except Exception as e:
        print(f"Error writing metadata file: {e}")
        # não apaga meta_path original, mas retorna False
        try:
            os.remove(tmp_path)
        except:
            pass
        return False

    # rename atomico
    try:
        os.replace(tmp_path, meta_path)
    except Exception as e:
        print(f"Failed to finalize metadata file: {e}")
        try:
            os.remove(tmp_path)
        except:
            pass
        return False

    return True


def decrypt_meta_json(meta_path: str, user_password: bytearray) -> Optional[Dict[str, Any]]:
    """
    Decrypts the content of the .meta file and returns a dict.
    Returns None if decryption fails or if the file is missing/corrupted.

    DUAS CAMADAS:
    - Lê outer_salt, outer_nonce, outer_ciphertext,
      descriptografa para recuperar o JSON interno (meta_dict).
    - Então, lê meta_salt, meta_nonce, meta_ciphertext do JSON interno,
      descriptografa para retornar o dicionário de metadados original.
    """
    if not os.path.exists(meta_path):
        return None

    # Lê o arquivo final (camada externa)
    try:
        with open(meta_path, 'r') as f:
            final_meta = json.load(f)
    except Exception as e:
        print(f"Error reading meta file: {e}")
        return None

    # Extrai dados do outer_dict
    try:
        outer_salt = base64.b64decode(final_meta["outer_salt"])
        outer_nonce = base64.b64decode(final_meta["outer_nonce"])
        outer_ciphertext = base64.b64decode(final_meta["outer_ciphertext"])
    except Exception as e:
        print(f"Error decoding Base64 in metadata (outer layer): {e}")
        return None

    outer_key = generate_key_from_password(user_password, outer_salt, META_ARGON_PARAMS)
    outer_cipher = ChaCha20Poly1305(bytes(outer_key))
    try:
        inner_meta_str = outer_cipher.decrypt(outer_nonce, outer_ciphertext, None)
    except (InvalidTag, ValueError) as e:
        print(f"Failed to decrypt outer layer: {e}")
        return None
    finally:
        for i in range(len(outer_key)):
            outer_key[i] = 0

    # Agora, inner_meta_str deve conter o JSON da camada interna
    try:
        meta_dict = json.loads(inner_meta_str.decode())
    except Exception as e:
        print(f"Error parsing inner meta JSON: {e}")
        return None

    # ====================================
    # CAMADA INTERNA (mesmo que antes)
    # ====================================
    try:
        meta_salt = base64.b64decode(meta_dict["meta_salt"])
        meta_nonce = base64.b64decode(meta_dict["meta_nonce"])
        meta_cipher = base64.b64decode(meta_dict["meta_ciphertext"])
    except Exception as e:
        print(f"Error decoding Base64 in metadata (inner layer): {e}")
        return None

    meta_key = generate_key_from_password(user_password, meta_salt, META_ARGON_PARAMS)
    cipher = ChaCha20Poly1305(bytes(meta_key))
    try:
        meta_json_str = cipher.decrypt(meta_nonce, meta_cipher, None)
        meta = json.loads(meta_json_str.decode())
        if not isinstance(meta, dict):
            raise ValueError("Metadata is not a valid dictionary.")
        if not ("salt" in meta or "decoy_salt" in meta or "real_salt" in meta):
            # Campo "salt" ou "decoy_salt" ou "real_salt" deve estar presente
            raise ValueError("Expected salt field missing in metadata.")
        return meta
    except (InvalidTag, ValueError) as e:
        print(f"Failed to decrypt metadata: {e}")
        return None
    finally:
        for i in range(len(meta_key)):
            meta_key[i] = 0
