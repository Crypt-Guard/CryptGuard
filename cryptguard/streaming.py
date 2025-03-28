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

    # Garante limite
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

    aad_dict = {
        "file_type": file_type,
        "original_ext": original_ext,
        "volume_type": "normal"
    }
    aad_base = json.dumps(aad_dict, sort_keys=True).encode()

    tmp_enc_path = enc_path + ".tmp"  # Arquivo temporário
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
                if chunk_index % 5 == 0 or processed == file_size:
                    progress = processed / file_size * 100
                    sys.stdout.write(f"\rEncrypting: {progress:.1f}%")
                    sys.stdout.flush()

        # Concluiu a escrita do arquivo temporário
        success = True
        print("\nStreaming encryption completed.")
        meta_plain = {
            "salt": base64.b64encode(file_salt).decode(),
            "argon2_time_cost": argon_params["time_cost"],
            "argon2_memory_cost": argon_params["memory_cost"],
            "argon2_parallelism": argon_params["parallelism"],
            "volume_type": "normal",
            "file_type": file_type,
            "original_ext": original_ext,
            "streaming": True,
            "created_at": datetime.datetime.now().isoformat()
        }
        if key_file_hash:
            meta_plain["key_file_hash"] = key_file_hash

        # Renomeia o arquivo temporário para o arquivo final
        os.rename(tmp_enc_path, enc_path)

        try:
            encrypt_meta_json(enc_path + ".meta", meta_plain, password)
        except OSError as e:
            print(f"Could not write meta file: {e}")
        return enc_path
    finally:
        # Limpeza de chave
        for i in range(len(derived_key)):
            derived_key[i] = 0

        # Se falhou no meio, remover o arquivo temporário
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
        f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        f"{meta_plain.get('original_ext','')}"
    )
    out_path = os.path.join(folder, out_name)

    success = True

    try:
        with open(enc_path, 'rb') as fin, open(out_path, 'wb') as fout:
            chunk_index = 0
            while True:
                header = fin.read(4)
                if not header:
                    break
                if len(header) < 4:
                    print("Corrupted file (incomplete header)!")
                    success = False
                    break
                block_len = struct.unpack('>I', header)[0]

                # Verificar se block_len é razoável
                if block_len > config.MAX_CHUNK_SIZE * 2:
                    # Por exemplo, permitir no máximo 2x chunk_size, ajustável a critério
                    print("Corrupted file or block_len too large!")
                    success = False
                    break

                block = fin.read(block_len)
                if len(block) < block_len:
                    print("Corrupted file (incomplete block)!")
                    success = False
                    break

                if chunk_index >= 2**96:
                    print("Error: chunk_index exceeded 2^96, invalid nonce.")
                    success = False
                    break

                plaintext, _ = decrypt_chunk(header + block, derived_key, 0, aad_base, chunk_index)
                if plaintext is None:
                    print("Decryption failed for a chunk!")
                    success = False
                    break
                fout.write(plaintext)
                chunk_index += 1

        if success:
            print(f"\nDecrypted file saved as: {out_name}")
        else:
            print("Decryption interrupted due to an error. Removing incomplete output.")
            try:
                os.remove(out_path)
            except Exception:
                pass
    finally:
        for i in range(len(derived_key)):
            derived_key[i] = 0
