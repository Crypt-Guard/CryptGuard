# hidden_volume.py

import os
import base64
import datetime
import time
import random
import secrets
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from rs_codec import rs_encode_data, rs_decode_data
from argon_utils import generate_key_from_password, get_argon2_parameters_for_encryption
from password_utils import validate_key_file, get_combined_password, choose_auth_method, validate_password
from metadata import encrypt_meta_json, decrypt_meta_json
from utils import generate_unique_filename, generate_ephemeral_token, clear_screen
from single_shot import decrypt_data_single
from streaming import decrypt_data_streaming
from config import MAX_ATTEMPTS

def encrypt_data_raw_chacha(data: bytes, password: bytearray, argon_params: dict):
    salt = secrets.token_bytes(32)
    key = generate_key_from_password(password, salt, argon_params)
    cipher = ChaCha20Poly1305(bytes(key))
    try:
        nonce = secrets.token_bytes(12)
        ciphertext = cipher.encrypt(nonce, data, None)
    finally:
        for i in range(len(key)):
            key[i] = 0

    return {
        'ciphertext': ciphertext,
        'nonce': base64.b64encode(nonce).decode(),
        'salt': base64.b64encode(salt).decode(),
        'argon2_time_cost': argon_params["time_cost"],
        'argon2_memory_cost': argon_params["memory_cost"],
        'argon2_parallelism': argon_params["parallelism"]
    }


def decrypt_data_raw_chacha(enc_dict: dict, password: bytearray) -> bytes:
    salt = base64.b64decode(enc_dict['salt'])
    argon_params = {
        'time_cost': enc_dict['argon2_time_cost'],
        'memory_cost': enc_dict['argon2_memory_cost'],
        'parallelism': enc_dict['argon2_parallelism']
    }
    key = generate_key_from_password(password, salt, argon_params)
    cipher = ChaCha20Poly1305(bytes(key))
    try:
        nonce = base64.b64decode(enc_dict['nonce'])
        ciphertext = enc_dict['ciphertext']
        return cipher.decrypt(nonce, ciphertext, None)
    finally:
        for i in range(len(key)):
            key[i] = 0


def encrypt_hidden_volume():
    """
    Cria volume oculto: 
    - Encripta 2 arquivos (falso, real) sem RS,
    - Concatena com padding,
    - Aplica RS no final, e salva meta cifrado com a senha do volume falso.
    """
    clear_screen()
    print("=== CRIPTOGRAFAR VOLUME OCULTO ===")
    file_falso = os.path.normpath(input("Caminho do arquivo para volume falso: ").strip())
    file_real = os.path.normpath(input("Caminho do arquivo para volume real: ").strip())

    if not os.path.exists(file_falso) or not os.path.exists(file_real):
        print("Um dos arquivos não foi encontrado!")
        input("\nPressione Enter para continuar...")
        return

    print("\nVolume Falso:")
    pwd_falso, key_file_hash_falso = get_combined_password()
    argon_params_falso = get_argon2_parameters_for_encryption()

    print("\nVolume Real:")
    pwd_real, key_file_hash_real = get_combined_password()
    argon_params_real = get_argon2_parameters_for_encryption()

    with open(file_falso, 'rb') as f:
        data_falso = f.read()
    with open(file_real, 'rb') as f:
        data_real = f.read()

    enc_falso_dict = encrypt_data_raw_chacha(data_falso, pwd_falso, argon_params_falso)
    enc_real_dict  = encrypt_data_raw_chacha(data_real,  pwd_real,  argon_params_real)

    falso_cipher = enc_falso_dict['ciphertext']
    real_cipher  = enc_real_dict['ciphertext']

    hidden_falso_length = len(falso_cipher)
    hidden_real_length  = len(real_cipher)
    hidden_padding = secrets.token_bytes(random.randint(512, 2048))
    hidden_padding_length = len(hidden_padding)

    combined = falso_cipher + hidden_padding + real_cipher
    combined_rs = rs_encode_data(combined)

    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    os.makedirs(folder, exist_ok=True)
    hidden_filename = generate_unique_filename("hidden_volume", ".enc")
    hidden_path = os.path.join(folder, hidden_filename)
    with open(hidden_path, 'wb') as fout:
        fout.write(combined_rs)

    hidden_token = generate_ephemeral_token(128)
    hidden_token_hash = hashlib.sha256(hidden_token.encode()).hexdigest()

    meta_plain = {
        'volume_type': "hidden",
        'hidden_falso_length': hidden_falso_length,
        'hidden_padding_length': hidden_padding_length,
        'hidden_real_length': hidden_real_length,
        'falso_nonce': enc_falso_dict['nonce'],
        'real_nonce': enc_real_dict['nonce'],
        'falso_salt': enc_falso_dict['salt'],
        'real_salt': enc_real_dict['salt'],
        'falso_argon2_time_cost': enc_falso_dict['argon2_time_cost'],
        'falso_argon2_memory_cost': enc_falso_dict['argon2_memory_cost'],
        'falso_argon2_parallelism': enc_falso_dict['argon2_parallelism'],
        'real_argon2_time_cost': enc_real_dict['argon2_time_cost'],
        'real_argon2_memory_cost': enc_real_dict['argon2_memory_cost'],
        'real_argon2_parallelism': enc_real_dict['argon2_parallelism'],
        'created_at': datetime.datetime.now().isoformat(),
        'hidden_token_hash': hidden_token_hash
    }
    if key_file_hash_falso:
        meta_plain['falso_key_file_hash'] = key_file_hash_falso
    if key_file_hash_real:
        meta_plain['real_key_file_hash'] = key_file_hash_real

    encrypt_meta_json(hidden_path + ".meta", meta_plain, pwd_falso)

    print("\nVolume oculto criado com sucesso!")
    print(f"Arquivo: {hidden_filename}")
    print(f"Guarde o token efêmero para acesso ao volume real: {hidden_token}")
    input("\nPressione Enter para continuar...")


def decrypt_file(encrypted_file: str, password: bytearray):
    """
    Detecta se 'volume_type' é normal ou hidden e chama a rotina apropriada.
    """
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    file_path = os.path.join(folder, encrypted_file)
    meta_path = file_path + ".meta"

    meta_plain = decrypt_meta_json(meta_path, password)
    if not meta_plain:
        print("Falha ao decifrar metadados (senha incorreta ou corrompidos)!")
        input("\nPressione Enter para continuar...")
        return

    volume_type = meta_plain.get('volume_type', 'normal')

    # Se houver key_file_hash
    if volume_type == "normal" and 'key_file_hash' in meta_plain:
        if not validate_key_file(meta_plain['key_file_hash']):
            input("\nPressione Enter para continuar...")
            return
    elif volume_type == "hidden":
        if 'falso_key_file_hash' in meta_plain:
            print("Arquivo-chave detectado para o volume falso.")
            if not validate_key_file(meta_plain['falso_key_file_hash']):
                input("\nPressione Enter para continuar...")
                return
        if 'real_key_file_hash' in meta_plain:
            print("Arquivo-chave detectado para o volume real.")
            if not validate_key_file(meta_plain['real_key_file_hash']):
                input("\nPressione Enter para continuar...")
                return

    if volume_type == "hidden":
        # Volume Oculto
        token = input("Digite o token efêmero para acesso ao volume oculto: ")
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        if token_hash != meta_plain.get('hidden_token_hash'):
            print("Token incorreto!")
            input("\nPressione Enter para continuar...")
            return

        choice = input("Deseja descriptografar volume falso (f) ou volume real (r)? ").strip().lower()
        if choice not in ['f', 'r']:
            print("Opção inválida!")
            input("\nPressione Enter para continuar...")
            return

        with open(file_path, 'rb') as f:
            combined_rs = f.read()
        try:
            combined_data = rs_decode_data(combined_rs)
        except Exception:
            print("Erro ao decodificar dados RS do volume oculto!")
            input("\nPressione Enter para continuar...")
            return

        hidden_falso_length   = meta_plain['hidden_falso_length']
        hidden_padding_length = meta_plain['hidden_padding_length']
        hidden_real_length    = meta_plain['hidden_real_length']

        if choice == 'f':
            target_cipher = combined_data[:hidden_falso_length]
            salt_str = meta_plain['falso_salt']
            nonce_str = meta_plain['falso_nonce']
            argon_params_choice = {
                'time_cost': meta_plain['falso_argon2_time_cost'],
                'memory_cost': meta_plain['falso_argon2_memory_cost'],
                'parallelism': meta_plain['falso_argon2_parallelism']
            }
            print("\nDigite a senha do volume falso:")
        else:
            start_real = hidden_falso_length + hidden_padding_length
            end_real = start_real + hidden_real_length
            target_cipher = combined_data[start_real:end_real]
            salt_str = meta_plain['real_salt']
            nonce_str = meta_plain['real_nonce']
            argon_params_choice = {
                'time_cost': meta_plain['real_argon2_time_cost'],
                'memory_cost': meta_plain['real_argon2_memory_cost'],
                'parallelism': meta_plain['real_argon2_parallelism']
            }
            print("\nDigite a senha do volume real:")

        import getpass
        attempts = 0
        while attempts < MAX_ATTEMPTS:
            pwd_input = getpass.getpass("> ")
            if not validate_password(pwd_input):
                print("Senha não atende aos requisitos!")
                continue

            pwd_hidden_ba = bytearray(pwd_input.encode())
            enc_dict = {
                'ciphertext': target_cipher,
                'nonce': nonce_str,
                'salt': salt_str,
                'argon2_time_cost': argon_params_choice["time_cost"],
                'argon2_memory_cost': argon_params_choice["memory_cost"],
                'argon2_parallelism': argon_params_choice["parallelism"]
            }

            from cryptography.exceptions import InvalidTag
            try:
                decrypted_data = decrypt_data_raw_chacha(enc_dict, pwd_hidden_ba)
                break
            except InvalidTag:
                attempts += 1
                print("Falha na descriptografia do volume oculto (InvalidTag)!")
                if attempts >= MAX_ATTEMPTS:
                    print("Muitas tentativas! Aguarde antes de tentar novamente.")
                    time.sleep(30)
                    input("\nPressione Enter para continuar...")
                    return
                else:
                    time.sleep(2 ** attempts)
                    print("Senha incorreta! Tente novamente:")

            for i in range(len(pwd_hidden_ba)):
                pwd_hidden_ba[i] = 0
        else:
            return

        out_name = f"decrypted_hidden_{choice}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
        out_path = os.path.join(folder, out_name)
        with open(out_path, 'wb') as f:
            f.write(decrypted_data)
        print(f"\nVolume oculto ({'falso' if choice=='f' else 'real'}) descriptografado e salvo como: {out_name}")

    else:
        # Volume normal
        streaming = meta_plain.get('streaming', False)
        if streaming:
            decrypt_data_streaming(file_path, password)
        else:
            decrypt_data_single(file_path, password)

    input("\nPressione Enter para continuar...")


def change_real_volume_password():
    """
    Permite mudar a senha do VOLUME REAL sem expor o volume falso.
    Fluxo:
    1) Pede nome do arquivo .enc (volume oculto)
    2) Pede senha do volume falso (para decifrar .meta)
    3) Pede token do volume real (se for usado) e a senha REAL atual
    4) Decifra somente a parte REAL
    5) Pede nova senha do volume real (com get_combined_password ou single)
    6) Recripta a parte real com a nova senha e regrava combined
    """
    clear_screen()
    print("=== TROCAR SENHA DO VOLUME REAL (HIDDEN) ===")
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    files = [f for f in os.listdir(folder) if f.endswith('.enc')]

    if not files:
        print("Nenhum arquivo .enc encontrado!")
        input("\nPressione Enter para voltar...")
        return

    print("\nArquivos disponíveis:")
    for i, f in enumerate(files, 1):
        print(f"[{i}] {f}")

    try:
        choice = int(input("\nEscolha o arquivo (volume oculto): ")) - 1
        selected_file = files[choice]
    except Exception:
        print("Seleção inválida!")
        input("\nPressione Enter para continuar...")
        return

    file_path = os.path.join(folder, selected_file)
    meta_path = file_path + ".meta"

    print("\nDigite a senha do volume falso para decifrar os metadados:")
    pwd_falso_ba, _ = choose_auth_method()

    meta_plain = decrypt_meta_json(meta_path, pwd_falso_ba)
    if not meta_plain:
        print("Falha ao decifrar metadados com a senha do volume falso!")
        input("\nPressione Enter para continuar...")
        return
    if meta_plain.get('volume_type','normal') != 'hidden':
        print("Este arquivo não é um volume oculto!")
        input("\nPressione Enter para continuar...")
        return

    # Precisamos checar se tem key_file_hash do real
    if 'real_key_file_hash' in meta_plain:
        print("Arquivo-chave detectado para o volume real.")
        if not validate_key_file(meta_plain['real_key_file_hash']):
            input("\nPressione Enter para continuar...")
            return

    # Lemos o combined
    with open(file_path, 'rb') as f:
        combined_rs = f.read()

    try:
        combined_data = rs_decode_data(combined_rs)
    except Exception:
        print("Erro ao decodificar dados RS do volume oculto!")
        input("\nPressione Enter para continuar...")
        return

    hidden_falso_length   = meta_plain['hidden_falso_length']
    hidden_padding_length = meta_plain['hidden_padding_length']
    hidden_real_length    = meta_plain['hidden_real_length']

    start_real = hidden_falso_length + hidden_padding_length
    end_real = start_real + hidden_real_length

    falso_cipher = combined_data[:hidden_falso_length]
    real_cipher  = combined_data[start_real:end_real]
    padding      = combined_data[hidden_falso_length : start_real]

    # Decifrar a parte REAL com a senha ATUAL do volume real
    print("\nAgora, digite a senha ATUAL do volume real (para decifrar a parte real):")
    real_salt_b64 = meta_plain['real_salt']
    real_nonce_b64 = meta_plain['real_nonce']
    argon_params_real = {
        'time_cost': meta_plain['real_argon2_time_cost'],
        'memory_cost': meta_plain['real_argon2_memory_cost'],
        'parallelism': meta_plain['real_argon2_parallelism']
    }

    # Precisamos decifrar (single-shot) a parte real
    attempts = 0
    real_plain_data = None
    while attempts < MAX_ATTEMPTS:
        import getpass
        pwd_real_old = getpass.getpass("> ")
        if not validate_password(pwd_real_old):
            print("Senha não atende aos requisitos!")
            continue

        pwd_real_ba = bytearray(pwd_real_old.encode())
        enc_dict = {
            'ciphertext': real_cipher,
            'nonce': real_nonce_b64,
            'salt': real_salt_b64,
            'argon2_time_cost': argon_params_real["time_cost"],
            'argon2_memory_cost': argon_params_real["memory_cost"],
            'argon2_parallelism': argon_params_real["parallelism"]
        }
        try:
            real_plain_data = decrypt_data_raw_chacha(enc_dict, pwd_real_ba)
            break
        except InvalidTag:
            attempts += 1
            print("Falha na descriptografia da parte real (senha incorreta)!")
            if attempts >= MAX_ATTEMPTS:
                print("Muitas tentativas! Abortando.")
                input("\nPressione Enter para continuar...")
                return
            else:
                time.sleep(2 ** attempts)
                print("Tente novamente:")
        finally:
            for i in range(len(pwd_real_ba)):
                pwd_real_ba[i] = 0

    if real_plain_data is None:
        return

    # 5) Pedir NOVA senha do volume real
    print("\nSenha antiga validada. Agora vamos definir a NOVA senha do volume real:")
    pwd_real_new_ba, key_file_hash_new_real = choose_auth_method()
    argon_params_new_real = get_argon2_parameters_for_encryption()

    # 6) Recriptar a parte real com a NOVA senha
    enc_real_dict_new = encrypt_data_raw_chacha(real_plain_data, pwd_real_new_ba, argon_params_new_real)
    new_real_cipher = enc_real_dict_new['ciphertext']

    # Reconstruir combined: falso_cipher + padding + new_real_cipher
    combined_new = falso_cipher + padding + new_real_cipher
    combined_new_rs = rs_encode_data(combined_new)

    # Atualiza metadados: real_salt, real_nonce, e argon2 do real
    meta_plain['real_salt']              = enc_real_dict_new['salt']
    meta_plain['real_nonce']             = enc_real_dict_new['nonce']
    meta_plain['real_argon2_time_cost']  = enc_real_dict_new['argon2_time_cost']
    meta_plain['real_argon2_memory_cost'] = enc_real_dict_new['argon2_memory_cost']
    meta_plain['real_argon2_parallelism'] = enc_real_dict_new['argon2_parallelism']

    if key_file_hash_new_real:
        meta_plain['real_key_file_hash'] = key_file_hash_new_real
    else:
        # se existia key_file_hash antigo, mas não tem mais, podemos remover
        meta_plain.pop('real_key_file_hash', None)

    # 7) Sobrescrever o .enc e .enc.meta
    with open(file_path, 'wb') as f:
        f.write(combined_new_rs)

    encrypt_meta_json(file_path + ".meta", meta_plain, pwd_falso_ba)

    print("\nSenha do volume real atualizada com sucesso!")
    input("\nPressione Enter para continuar...")

