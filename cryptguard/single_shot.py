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
import config


def encrypt_data_single(data: bytes, password: bytearray,
                        file_type: str, original_ext: str = "",
                        key_file_hash: str = None):
    """
    Encrypt data in a single shot using Argon2id + ChaCha20Poly1305.
    """
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
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
        aad_base = (f'{{"file_type":"{file_type}","original_ext":"{original_ext}",'
                    f'"volume_type":"normal"}}').encode()
        # Criptografa todos os dados em um único chunk
        block = encrypt_chunk(data, derived_key, aad_base, 0)
        filename = generate_unique_filename(file_type)
        enc_path = os.path.join(folder, filename)
        try:
            with open(enc_path, 'wb') as f:
                f.write(block)
        except OSError as e:
            print(f"Erro ao gravar arquivo criptografado: {e}")
            return

        # Monta metadados
        meta_plain = {
            "argon2_time_cost": argon_params["time_cost"],
            "argon2_memory_cost": argon_params["memory_cost"],
            "argon2_parallelism": argon_params["parallelism"],
            "salt": base64.b64encode(file_salt).decode(),
            "file_type": file_type,
            "original_ext": original_ext,
            "volume_type": "normal",
            "created_at": datetime.datetime.now().isoformat(),
            "use_rs": config.USE_RS,
            "version": config.META_VERSION
        }
        if config.USE_RS:
            meta_plain["rs_parity"] = config.RS_PARITY_BYTES
        if key_file_hash:
            meta_plain["key_file_hash"] = key_file_hash
        if config.SIGN_METADATA:
            import hmac, hashlib
            sig = hmac.new(bytes(derived_key), block, hashlib.sha256).hexdigest()
            meta_plain["signature"] = sig

        meta_ok = encrypt_meta_json(enc_path + ".meta", meta_plain, password)
        if not meta_ok:
            print("Encryption failed during metadata writing.")
            # remove arquivo .enc se meta falhou
            try:
                os.remove(enc_path)
            except OSError:
                pass
            return

        print(f"\nEncrypted file saved as: {filename}")
    finally:
        # limpar chave derivada e senha
        for i in range(len(derived_key)):
            derived_key[i] = 0
        for i in range(len(password)):
            password[i] = 0


def decrypt_data_single(enc_path: str, password: bytearray):
    """
    Decrypts a single-shot encrypted file. Restores original extension if available.
    """
    if not os.path.exists(enc_path + ".meta"):
        print("Warning: Metadata file not found. Cannot proceed with decryption.")
        for i in range(len(password)):
            password[i] = 0
        return

    meta_plain = decrypt_meta_json(enc_path + ".meta", password)
    if not meta_plain:
        print("Failed to decrypt metadata (incorrect password or corrupted data)!")
        # limpar password
        for i in range(len(password)):
            password[i] = 0
        return

    # Ajusta configurações RS conforme meta (isolando global)
    old_use_rs = config.USE_RS
    old_rs_parity = config.RS_PARITY_BYTES
    config.USE_RS = meta_plain.get("use_rs", False)
    if "rs_parity" in meta_plain:
        config.RS_PARITY_BYTES = meta_plain["rs_parity"]
    try:
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

        aad_base = (f'{{"file_type":"{meta_plain["file_type"]}",'
                    f'"original_ext":"{meta_plain["original_ext"]}",'
                    f'"volume_type":"{meta_plain["volume_type"]}"}}').encode()

        try:
            with open(enc_path, 'rb') as f:
                file_data = f.read()
        except OSError as e:
            print(f"Error reading encrypted file: {e}")
            return

        # Verifica assinatura de integridade se presente
        if "signature" in meta_plain:
            import hmac, hashlib
            calc_sig = hmac.new(bytes(derived_key), file_data, hashlib.sha256).hexdigest()
            if calc_sig != meta_plain["signature"]:
                print("Warning: encrypted file signature mismatch! Aborting decryption.")
                # limpeza
                for i in range(len(derived_key)):
                    derived_key[i] = 0
                for i in range(len(password)):
                    password[i] = 0
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
        out_name = (f'decrypted_{meta_plain["file_type"]}_'
                    f'{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}_'
                    f'{secrets.token_hex(2)}'
                    f'{meta_plain.get("original_ext", "")}')
        out_path = os.path.join(folder, out_name)
        try:
            with open(out_path, 'wb') as f:
                f.write(plaintext)
            print(f"\nDecrypted file saved as: {out_name}")
        except OSError as e:
            print(f"Error writing decrypted file: {e}")
        finally:
            # limpar plaintext da memória
            try:
                buf = bytearray(plaintext)
                for i in range(len(buf)):
                    buf[i] = 0
            except Exception:
                pass
    finally:
        # Restaura configuração global de RS
        config.USE_RS = old_use_rs
        config.RS_PARITY_BYTES = old_rs_parity
        # limpar chave derivada e senha
        if 'derived_key' in locals():
            for i in range(len(derived_key)):
                derived_key[i] = 0
        for i in range(len(password)):
            password[i] = 0
