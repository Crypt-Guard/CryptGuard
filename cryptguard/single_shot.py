# single_shot.py
"""
Single-shot (non-streaming) encryption/decryption for smaller files.
"""

import os
import base64
import datetime
import secrets

from argon_utils import get_argon2_parameters_for_encryption, generate_key_from_password
from chunk_crypto import encrypt_chunk, decrypt_chunk
from metadata import encrypt_meta_json, decrypt_meta_json
from utils import generate_unique_filename


def encrypt_data_single(data: bytes, password: bytearray,
                        file_type: str, original_ext: str = "",
                        key_file_hash: str = None):
    """
    Encrypt data in a single shot using Argon2 key derivation + ChaCha20Poly1305.
    Metadata is encrypted and stored in a .meta file.
    WARNING: For very large 'data', this will use a lot of memory.
    """
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    # Tentar criar pasta de saída
    try:
        os.makedirs(folder, exist_ok=True)
    except OSError as e:
        print(f"Warning: Could not create output folder: {e}")

    argon_params = get_argon2_parameters_for_encryption()
    file_salt = secrets.token_bytes(32)
    try:
        derived_key = generate_key_from_password(password, file_salt, argon_params)
    except MemoryError:
        print("MemoryError: Argon2 parameters might be too large for this system.")
        return

    try:
        aad_base = (
            f'{{"file_type":"{file_type}","original_ext":"{original_ext}",'
            f'"volume_type":"normal"}}'
        ).encode()
        enc_data = encrypt_chunk(data, derived_key, aad_base, 0)
        filename = generate_unique_filename(file_type)
        enc_path = os.path.join(folder, filename)
        with open(enc_path, 'wb') as f:
            f.write(enc_data)
        meta_plain = {
            "argon2_time_cost": argon_params["time_cost"],
            "argon2_memory_cost": argon_params["memory_cost"],
            "argon2_parallelism": argon_params["parallelism"],
            "salt": base64.b64encode(file_salt).decode(),
            "file_type": file_type,
            "original_ext": original_ext,
            "volume_type": "normal",
            "created_at": datetime.datetime.now().isoformat(),
            "streaming": False
        }
        if key_file_hash:
            meta_plain["key_file_hash"] = key_file_hash
        encrypt_meta_json(enc_path + ".meta", meta_plain, password)
        print(f"\nEncrypted file saved as: {filename}")
    finally:
        for i in range(len(derived_key)):
            derived_key[i] = 0


def decrypt_data_single(enc_path: str, password: bytearray):
    """
    Decrypts a single-shot encrypted file.
    Restores the original extension if available.
    """
    meta_plain = decrypt_meta_json(enc_path + ".meta", password)
    if not meta_plain:
        print("Failed to decrypt metadata (incorrect password or corrupted data)!")
        return

    file_salt = base64.b64decode(meta_plain["salt"])
    argon_params = {
        "time_cost": meta_plain["argon2_time_cost"],
        "memory_cost": meta_plain["argon2_memory_cost"],
        "parallelism": meta_plain["argon2_parallelism"]
    }
    try:
        derived_key = generate_key_from_password(password, file_salt, argon_params)
    except MemoryError:
        print("MemoryError: Argon2 parameters might be too large for this system.")
        return

    try:
        aad_base = (
            f'{{"file_type":"{meta_plain["file_type"]}",'
            f'"original_ext":"{meta_plain["original_ext"]}",'
            f'"volume_type":"{meta_plain["volume_type"]}"}}'
        ).encode()

        try:
            with open(enc_path, 'rb') as f:
                file_data = f.read()
        except OSError as e:
            print(f"Error reading encrypted file: {e}")
            return

        plaintext, _ = decrypt_chunk(file_data, derived_key, 0, aad_base, 0)
        if plaintext is None:
            print("File decryption failed!")
            return
        folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
        try:
            os.makedirs(folder, exist_ok=True)
        except OSError as e:
            print(f"Warning: Could not create output folder: {e}")

        out_name = (
            f'decrypted_{meta_plain["file_type"]}_'
            f'{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}'
            f'{meta_plain.get("original_ext", "")}'
        )
        out_path = os.path.join(folder, out_name)
        try:
            with open(out_path, 'wb') as f:
                f.write(plaintext)
            print(f"\nDecrypted file saved as: {out_name}")
        except OSError as e:
            print(f"Error writing decrypted file: {e}")
    finally:
        for i in range(len(derived_key)):
            derived_key[i] = 0
