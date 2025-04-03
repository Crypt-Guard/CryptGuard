# streaming.py
"""
Streaming encryption/decryption for large files, processing data in chunks.
"""

import os
import sys
import base64
import datetime
import secrets
import struct
import json

import config
from argon_utils import get_argon2_parameters_for_encryption, generate_key_from_password
from chunk_crypto import encrypt_chunk, decrypt_chunk
from metadata import encrypt_meta_json, decrypt_meta_json
from utils import generate_unique_filename

def encrypt_data_streaming(file_path: str, password: bytearray,
                           file_type: str, original_ext: str = "",
                           key_file_hash: str = None, chunk_size: int = None):
    """
    Encrypts a large file in streaming mode, reading it in chunks.
    If chunk_size is not specified, uses the default CHUNK_SIZE.
    """

    if chunk_size is None:
        chunk_size = config.CHUNK_SIZE

    if chunk_size > config.MAX_CHUNK_SIZE:
        print(f"Chunk size too large; forcing {config.MAX_CHUNK_SIZE} bytes.")
        chunk_size = config.MAX_CHUNK_SIZE

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
        return None

    filename = generate_unique_filename(file_type)
    enc_path = os.path.join(folder, filename)

    # JSON para AAD
    aad_dict = {
        "file_type": file_type,
        "original_ext": original_ext,
        "volume_type": "normal"
    }
    aad_base = json.dumps(aad_dict, sort_keys=True).encode()

    tmp_enc_path = enc_path + ".tmp"
    success = False

    try:
        file_size = os.path.getsize(file_path)
        processed = 0
        chunk_index = 0
        with open(file_path, 'rb') as fin, open(tmp_enc_path, 'wb') as fout:
            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break

                if chunk_index >= 2**96:
                    print("Error: chunk_index exceeded 2^96, cannot form a valid nonce.")
                    break

                block = encrypt_chunk(chunk, derived_key, aad_base, chunk_index)
                fout.write(block)
                processed += len(chunk)
                chunk_index += 1

                # Exemplo de progresso
                if chunk_index % 5 == 0 or processed == file_size:
                    progress = processed / file_size * 100
                    sys.stdout.write(f"\rEncrypting: {progress:.1f}%")
                    sys.stdout.flush()

        success = True
        print("\nStreaming encryption completed.")

        # rename tmp -> enc
        try:
            os.replace(tmp_enc_path, enc_path)
        except Exception as e:
            print(f"Failed to finalize encrypted file: {e}")
            success = False

        if success:
            # Salvar meta
            meta_plain = {
                "salt": base64.b64encode(file_salt).decode(),
                "argon2_time_cost": argon_params["time_cost"],
                "argon2_memory_cost": argon_params["memory_cost"],
                "argon2_parallelism": argon_params["parallelism"],
                "volume_type": "normal",
                "file_type": file_type,
                "original_ext": original_ext,
                "streaming": True,
                "created_at": datetime.datetime.now().isoformat(),
                "use_rs": config.USE_RS
            }
            if key_file_hash:
                meta_plain["key_file_hash"] = key_file_hash

            if not encrypt_meta_json(enc_path + ".meta", meta_plain, password):
                print("Failed to write meta file.")
                try:
                    os.remove(enc_path)
                except OSError:
                    pass
                success = False

        return enc_path if success else None

    finally:
        # Limpar derivada e senha
        for i in range(len(derived_key)):
            derived_key[i] = 0
        for i in range(len(password)):
            password[i] = 0

        if not success:
            try:
                os.remove(tmp_enc_path)
            except OSError:
                pass


def decrypt_data_streaming(enc_path: str, password: bytearray):
    """
    Decrypts an encrypted file in streaming mode, reading each block individually.
    """

    meta_plain = decrypt_meta_json(enc_path + ".meta", password)
    if not meta_plain:
        print("Failed to decrypt metadata (incorrect password or corrupted)!")
        for i in range(len(password)):
            password[i] = 0
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
        for i in range(len(password)):
            password[i] = 0
        return

    aad_dict = {
        "file_type": meta_plain["file_type"],
        "original_ext": meta_plain["original_ext"],
        "volume_type": meta_plain["volume_type"]
    }
    aad_base = json.dumps(aad_dict, sort_keys=True).encode()

    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    try:
        os.makedirs(folder, exist_ok=True)
    except OSError as e:
        print(f"Warning: Could not create output folder: {e}")

    out_name = (
        f"decrypted_{meta_plain['file_type']}_"
        f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_"
        f"{secrets.token_hex(2)}"
        f"{meta_plain.get('original_ext','')}"
    )
    out_path = os.path.join(folder, out_name)

    success = True

    try:
        with open(enc_path, 'rb') as fin, open(out_path, 'wb') as fout:
            chunk_index = 0
            error_occurred = False

            while True:
                length_bytes = fin.read(4)
                if not length_bytes:
                    break  # EOF

                if len(length_bytes) < 4:
                    print("Corrupted file (incomplete header)!")
                    error_occurred = True
                    break

                block_len = struct.unpack('>I', length_bytes)[0]

                if block_len > config.MAX_CHUNK_SIZE * 2:
                    print("Corrupted file or block_len too large!")
                    error_occurred = True
                    break

                block_data = fin.read(block_len)
                if len(block_data) < block_len:
                    print("Corrupted file (incomplete block)!")
                    error_occurred = True
                    break

                if chunk_index >= 2**96:
                    print("Error: chunk_index exceeded 2^96, invalid nonce.")
                    error_occurred = True
                    break

                plaintext, _ = decrypt_chunk(length_bytes + block_data,
                                             derived_key, 0, aad_base,
                                             chunk_index)
                if plaintext is None:
                    print("Decryption failed for a chunk!")
                    error_occurred = True
                    break

                fout.write(plaintext)
                chunk_index += 1

            if error_occurred:
                success = False

    finally:
        for i in range(len(derived_key)):
            derived_key[i] = 0
        for i in range(len(password)):
            password[i] = 0

        if not success:
            print("Decryption interrupted due to an error. Removing incomplete output.")
            try:
                os.remove(out_path)
            except Exception:
                pass

    if success:
        print(f"\nDecrypted file saved as: {out_name}")
