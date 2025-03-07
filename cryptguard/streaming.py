# streaming.py

import os
import sys
import base64
import datetime
import secrets
import struct

from config import CHUNK_SIZE, STREAMING_THRESHOLD
from argon_utils import get_argon2_parameters_for_encryption, generate_key_from_password
from chunk_crypto import encrypt_chunk, decrypt_chunk
from metadata import encrypt_meta_json, decrypt_meta_json
from utils import generate_unique_filename

def encrypt_data_streaming(file_path: str, password: bytearray,
                           file_type: str, original_ext: str = "",
                           key_file_hash: str = None, chunk_size: int = None):
    """
    Criptografa um arquivo grande em modo streaming, processando-o em chunks.
    Se chunk_size não for especificado, usa o valor padrão CHUNK_SIZE.
    """
    if chunk_size is None:
        chunk_size = CHUNK_SIZE

    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    os.makedirs(folder, exist_ok=True)

    argon_params = get_argon2_parameters_for_encryption()
    file_salt = secrets.token_bytes(32)
    derived_key = generate_key_from_password(password, file_salt, argon_params)

    filename = generate_unique_filename(file_type)
    enc_path = os.path.join(folder, filename)

    import json
    aad_dict = {
        "file_type": file_type,
        "original_ext": original_ext,
        "volume_type": "normal"
    }
    aad_base = json.dumps(aad_dict, sort_keys=True).encode()

    try:
        file_size = os.path.getsize(file_path)
        processed = 0
        with open(file_path, 'rb') as fin, open(enc_path, 'wb') as fout:
            chunk_index = 0
            while True:
                chunk = fin.read(chunk_size)
                if not chunk:
                    break
                block = encrypt_chunk(chunk, derived_key, aad_base, chunk_index)
                fout.write(block)
                processed += len(chunk)
                chunk_index += 1
                progress = processed / file_size * 100
                sys.stdout.write(f"\rCriptografando: {progress:.1f}%")
                sys.stdout.flush()
        print("\nCriptografia (streaming) concluída.")
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
            "total_encrypted_bytes": os.path.getsize(enc_path),
            "chunk_size": chunk_size
        }
        if key_file_hash:
            meta_plain["key_file_hash"] = key_file_hash
        encrypt_meta_json(enc_path + ".meta", meta_plain, password)
        return enc_path
    finally:
        for i in range(len(derived_key)):
            derived_key[i] = 0

def decrypt_data_streaming(enc_path: str, password: bytearray):
    """
    Descriptografa um arquivo cifrado em modo streaming, lendo cada bloco individualmente,
    de forma a evitar carregar o arquivo inteiro em memória.
    """
    meta_plain = decrypt_meta_json(enc_path + ".meta", password)
    if not meta_plain:
        print("Falha ao decifrar metadados (senha incorreta ou corrompidos)!")
        return

    file_salt = base64.b64decode(meta_plain["salt"])
    argon_params = {
        "time_cost": meta_plain["argon2_time_cost"],
        "memory_cost": meta_plain["argon2_memory_cost"],
        "parallelism": meta_plain["argon2_parallelism"]
    }
    derived_key = generate_key_from_password(password, file_salt, argon_params)

    try:
        import json
        aad_dict = {
            "file_type": meta_plain["file_type"],
            "original_ext": meta_plain["original_ext"],
            "volume_type": meta_plain["volume_type"]
        }
        aad_base = json.dumps(aad_dict, sort_keys=True).encode()

        folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
        out_name = (
            f"decrypted_{meta_plain['file_type']}_"
            f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            f"{meta_plain.get('original_ext','')}"
        )
        out_path = os.path.join(folder, out_name)

        with open(enc_path, 'rb') as fin, open(out_path, 'wb') as fout:
            chunk_index = 0
            while True:
                header = fin.read(4)
                if not header:
                    break
                if len(header) < 4:
                    print("Arquivo corrompido (header incompleto)!")
                    break
                block_len = struct.unpack('>I', header)[0]
                rs_block = fin.read(block_len)
                if len(rs_block) < block_len:
                    print("Arquivo corrompido (bloco incompleto)!")
                    break
                block_data = header + rs_block
                plaintext, _ = decrypt_chunk(block_data, derived_key, 0, aad_base, chunk_index)
                if plaintext is None:
                    print("Falha em um chunk!")
                    break
                fout.write(plaintext)
                chunk_index += 1
        print(f"\nArquivo descriptografado salvo como: {out_name}")
    finally:
        for i in range(len(derived_key)):
            derived_key[i] = 0
