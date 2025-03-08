# single_shot.py

import os
import base64
import datetime
import secrets

from argon_utils import get_argon2_parameters_for_encryption, generate_key_from_password
from chunk_crypto import encrypt_chunk, decrypt_chunk
from metadata import encrypt_meta_json, decrypt_meta_json
from utils import generate_unique_filename

def encrypt_data_single(data: bytes, password: bytearray, file_type: str,
                        original_ext: str = "", key_file_hash: str = None):
    """
    Criptografa os dados em um único chunk utilizando Argon2 para derivar a chave,
    adiciona AAD e salva o arquivo cifrado. Os metadados (salt, parâmetros) são cifrados
    e salvos num arquivo .meta.
    """
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    os.makedirs(folder, exist_ok=True)

    argon_params = get_argon2_parameters_for_encryption()
    file_salt = secrets.token_bytes(32)
    derived_key = generate_key_from_password(password, file_salt, argon_params)

    try:
        aad_base = (
            f'{{"file_type":"{file_type}","original_ext":"{original_ext}","volume_type":"normal"}}'
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
        print(f"\nArquivo criptografado salvo como: {filename}")
    finally:
        for i in range(len(derived_key)):
            derived_key[i] = 0

def decrypt_data_single(enc_path: str, password: bytearray):
    """
    Decifra um arquivo cifrado (single-shot) utilizando os metadados para derivar a chave.
    O arquivo descriptografado é salvo com a extensão original, se disponível.
    """
    meta_plain = decrypt_meta_json(enc_path + ".meta", password)
    if not meta_plain:
        print("Falha ao decifrar metadados (senha incorreta ou dados corrompidos)!")
        return

    file_salt_b64 = meta_plain["salt"]
    file_salt = base64.b64decode(file_salt_b64)
    argon_params = {
        "time_cost": meta_plain["argon2_time_cost"],
        "memory_cost": meta_plain["argon2_memory_cost"],
        "parallelism": meta_plain["argon2_parallelism"]
    }
    derived_key = generate_key_from_password(password, file_salt, argon_params)

    try:
        aad_base = (
            f'{{"file_type":"{meta_plain["file_type"]}","original_ext":"{meta_plain["original_ext"]}",'
            f'"volume_type":"{meta_plain["volume_type"]}"}}'
        ).encode()
        with open(enc_path, 'rb') as f:
            file_data = f.read()
        plaintext, _ = decrypt_chunk(file_data, derived_key, 0, aad_base, 0)
        if plaintext is None:
            print("Falha na descriptografia do arquivo!")
            return
        folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
        out_name = (
            f'decrypted_{meta_plain["file_type"]}_'
            f'{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}'
            f'{meta_plain.get("original_ext","")}'
        )
        out_path = os.path.join(folder, out_name)
        with open(out_path, 'wb') as f:
            f.write(plaintext)
        print(f"\nArquivo descriptografado salvo como: {out_name}")
    finally:
        for i in range(len(derived_key)):
            derived_key[i] = 0
