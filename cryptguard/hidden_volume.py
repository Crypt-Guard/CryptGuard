# hidden_volume.py

import os
import base64
import datetime
import time
import random
import secrets
import hashlib
import getpass

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from rs_codec import rs_encode_data, rs_decode_data
from argon_utils import generate_key_from_password, get_argon2_parameters_for_encryption
from password_utils import validate_key_file, choose_auth_method, validate_password
from metadata import encrypt_meta_json, decrypt_meta_json
from utils import generate_unique_filename, generate_ephemeral_token, clear_screen
from single_shot import decrypt_data_single
from streaming import decrypt_data_streaming
from config import MAX_ATTEMPTS

def encrypt_data_raw_chacha(data: bytes, password: bytearray, argon_params: dict, extra: bytes = None):
    """
    Criptografa dados usando ChaCha20Poly1305.
    Suporta um parâmetro opcional 'extra' que, se fornecido, é concatenado à senha
    para derivar a chave (usado para volume real com token efêmero).
    """
    salt = secrets.token_bytes(32)
    key = generate_key_from_password(password, salt, argon_params, extra)
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

def decrypt_data_raw_chacha(enc_dict: dict, password: bytearray, extra: bytes = None) -> bytes:
    """
    Descriptografa dados cifrados por encrypt_data_raw_chacha.
    Usa o parâmetro opcional 'extra' na derivação da chave, se fornecido.
    """
    salt = base64.b64decode(enc_dict['salt'])
    argon_params = {
        'time_cost': enc_dict['argon2_time_cost'],
        'memory_cost': enc_dict['argon2_memory_cost'],
        'parallelism': enc_dict['argon2_parallelism']
    }
    key = generate_key_from_password(password, salt, argon_params, extra)
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
    Cria volume oculto com deniability aprimorada:
      - Criptografa dois arquivos (volume falso e volume real) sem RS,
      - Concatena com padding,
      - Aplica RS no final e salva metadados separados:
          * Meta Outer (volume falso) criptografado com a senha do volume falso, sem indicação de oculto.
          * Meta Inner (volume real) criptografado com a senha do volume real, contendo detalhes do volume real.
      
    O volume real é criptografado usando autenticação (senha + opcional arquivo‐chave)
    e um token efêmero, que é incorporado na derivação da chave.
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
    pwd_falso, key_file_hash_falso = choose_auth_method()
    argon_params_falso = get_argon2_parameters_for_encryption()

    print("\nVolume Real:")
    pwd_real, key_file_hash_real = choose_auth_method()
    argon_params_real = get_argon2_parameters_for_encryption()

    # Gerar token efêmero para o volume real
    token = generate_ephemeral_token(128)
    print(f"\nToken efêmero gerado para o volume real: {token}")
    token_bytes = token.encode()

    with open(file_falso, 'rb') as f:
        data_falso = f.read()
    with open(file_real, 'rb') as f:
        data_real = f.read()

    enc_falso_dict = encrypt_data_raw_chacha(data_falso, pwd_falso, argon_params_falso)
    enc_real_dict  = encrypt_data_raw_chacha(data_real, pwd_real, argon_params_real, extra=token_bytes)

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

    hidden_token_hash = hashlib.sha256(token.encode()).hexdigest()

    # Criar metadados externos (para volume falso) sem indicação de "hidden"
    meta_outer = {
        'hidden_falso_length': hidden_falso_length,
        'hidden_padding_length': hidden_padding_length,
        'hidden_real_length': hidden_real_length,
        'falso_nonce': enc_falso_dict['nonce'],
        'falso_salt': enc_falso_dict['salt'],
        'falso_argon2_time_cost': enc_falso_dict['argon2_time_cost'],
        'falso_argon2_memory_cost': enc_falso_dict['argon2_memory_cost'],
        'falso_argon2_parallelism': enc_falso_dict['argon2_parallelism'],
        'created_at': datetime.datetime.now().isoformat()
    }
    if key_file_hash_falso:
        meta_outer['falso_key_file_hash'] = key_file_hash_falso

    # Criar metadados internos (para volume real) com detalhes do volume oculto
    meta_inner = {
        'real_nonce': enc_real_dict['nonce'],
        'real_salt': enc_real_dict['salt'],
        'real_argon2_time_cost': enc_real_dict['argon2_time_cost'],
        'real_argon2_memory_cost': enc_real_dict['argon2_memory_cost'],
        'real_argon2_parallelism': enc_real_dict['argon2_parallelism'],
        'hidden_token_hash': hidden_token_hash
    }
    if key_file_hash_real:
        meta_inner['real_key_file_hash'] = key_file_hash_real

    # Salvar os metadados em dois arquivos separados:
    # Meta Outer: <hidden_path>.meta (acessível com senha do volume falso)
    # Meta Inner: <hidden_path>.meta_hidden (acessível com senha do volume real)
    encrypt_meta_json(hidden_path + ".meta", meta_outer, pwd_falso)
    encrypt_meta_json(hidden_path + ".meta_hidden", meta_inner, pwd_real)

    print("\nVolume oculto criado com sucesso!")
    print(f"Arquivo: {hidden_filename}")
    print("Guarde o token efêmero para acesso ao volume real com segurança.")
    input("\nPressione Enter para continuar...")

def decrypt_file(encrypted_file: str, outer_password: bytearray):
    """
    Detecta se o volume é normal ou hidden e chama a rotina apropriada.
    Para volumes ocultos, utiliza:
      - O arquivo .meta (metadados do volume falso), decifrável com outer_password.
      - O arquivo .meta_hidden (metadados do volume real), decifrável com a senha do volume real.
    No caso do volume real, o token efêmero (obtido anteriormente) é incorporado na derivação.
    Para volumes normais, utiliza autenticação unificada (senha + opcional arquivo‐chave).
    """
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    file_path = os.path.join(folder, encrypted_file)
    meta_path = file_path + ".meta"

    meta_outer = decrypt_meta_json(meta_path, outer_password)
    if not meta_outer:
        print("Falha ao decifrar metadados (senha incorreta ou dados corrompidos)!")
        input("\nPressione Enter para continuar...")
        return

    # Verifica se há metadados internos, que indicam volume oculto
    meta_hidden_path = file_path + ".meta_hidden"
    if os.path.exists(meta_hidden_path):
        is_hidden = True
    else:
        is_hidden = False

    if is_hidden:
        print("\nVolume oculto detectado.")
        if 'falso_key_file_hash' in meta_outer:
            print("Arquivo-chave detectado para o volume falso.")
            if not validate_key_file(meta_outer['falso_key_file_hash']):
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

        hidden_falso_length   = meta_outer['hidden_falso_length']
        hidden_padding_length = meta_outer['hidden_padding_length']
        hidden_real_length    = meta_outer['hidden_real_length']

        choice = input("Deseja descriptografar volume falso (f) ou volume real (r)? ").strip().lower()
        if choice not in ['f', 'r']:
            print("Opção inválida!")
            input("\nPressione Enter para continuar...")
            return

        if choice == 'f':
            target_cipher = combined_data[:hidden_falso_length]
            salt_str = meta_outer['falso_salt']
            nonce_str = meta_outer['falso_nonce']
            argon_params_choice = {
                'time_cost': meta_outer['falso_argon2_time_cost'],
                'memory_cost': meta_outer['falso_argon2_memory_cost'],
                'parallelism': meta_outer['falso_argon2_parallelism']
            }
            print("\nUsando autenticação do volume falso já fornecida.")
            combined_pwd = outer_password
            extra_factor = None
        else:
            print("\nAutentique o volume real (senha + opcional arquivo-chave):")
            combined_pwd, _ = choose_auth_method()
            token = getpass.getpass("Digite o token efêmero para acesso ao volume oculto: ")
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            meta_inner = decrypt_meta_json(meta_hidden_path, combined_pwd)
            if not meta_inner:
                print("Falha ao decifrar metadados do volume real (senha incorreta ou dados corrompidos)!")
                input("\nPressione Enter para continuar...")
                return
            if token_hash != meta_inner.get('hidden_token_hash'):
                print("Token incorreto!")
                input("\nPressione Enter para continuar...")
                return
            target_cipher = combined_data[hidden_falso_length + hidden_padding_length : hidden_falso_length + hidden_padding_length + hidden_real_length]
            salt_str = meta_inner['real_salt']
            nonce_str = meta_inner['real_nonce']
            argon_params_choice = {
                'time_cost': meta_inner['real_argon2_time_cost'],
                'memory_cost': meta_inner['real_argon2_memory_cost'],
                'parallelism': meta_inner['real_argon2_parallelism']
            }
            extra_factor = token.encode()

        attempts = 0
        decrypted_data = None
        while attempts < MAX_ATTEMPTS:
            enc_dict = {
                'ciphertext': target_cipher,
                'nonce': nonce_str,
                'salt': salt_str,
                'argon2_time_cost': argon_params_choice["time_cost"],
                'argon2_memory_cost': argon_params_choice["memory_cost"],
                'argon2_parallelism': argon_params_choice["parallelism"]
            }
            try:
                decrypted_data = decrypt_data_raw_chacha(enc_dict, combined_pwd, extra=extra_factor)
                break
            except InvalidTag:
                attempts += 1
                print("Falha na descriptografia (InvalidTag)!")
                if attempts >= MAX_ATTEMPTS:
                    print("Muitas tentativas! Aguarde antes de tentar novamente.")
                    time.sleep(30)
                    input("\nPressione Enter para continuar...")
                    return
                else:
                    time.sleep(2 ** attempts)
                    print("Autenticação incorreta! Tente novamente:")
        else:
            return

        out_name = f"decrypted_hidden_{'falso' if choice=='f' else 'real'}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
        out_path = os.path.join(folder, out_name)
        with open(out_path, 'wb') as f:
            f.write(decrypted_data)
        print(f"\nVolume oculto ({'falso' if choice=='f' else 'real'}) descriptografado e salvo como: {out_name}")

    else:
        # Volume normal
        print("\nVolume normal detectado.")
        # Utilize a senha outer já fornecida sem solicitar novamente.
        meta_plain = decrypt_meta_json(meta_path, outer_password)
        if not meta_plain:
            print("Falha ao decifrar metadados (senha incorreta ou dados corrompidos)!")
            input("\nPressione Enter para continuar...")
            return
        if 'key_file_hash' in meta_plain:
            if not validate_key_file(meta_plain['key_file_hash']):
                input("\nPressione Enter para continuar...")
                return
        print("\nDescriptografando volume normal com a senha fornecida...")
        if meta_plain.get('streaming', False):
            decrypt_data_streaming(file_path, outer_password)
        else:
            decrypt_data_single(file_path, outer_password)

    input("\nPressione Enter para continuar...")

def change_real_volume_password():
    """
    Permite trocar a senha do VOLUME REAL (parte real do volume oculto) sem expor o volume falso.
    Fluxo:
      1) Seleciona o arquivo .enc (volume oculto).
      2) Autentica com o volume falso para decifrar os metadados outer.
      3) Autentica o volume real (senha + opcional arquivo-chave) juntamente com o token efêmero.
      4) Descriptografa a parte real.
      5) Solicita a nova autenticação para o volume real.
      6) Recriptografa a parte real com a nova autenticação e atualiza os metadados inner.
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
    meta_outer_path = file_path + ".meta"
    meta_inner_path = file_path + ".meta_hidden"

    print("\nAutentique o volume falso para decifrar os metadados outer:")
    pwd_falso, _ = choose_auth_method()

    meta_outer = decrypt_meta_json(meta_outer_path, pwd_falso)
    if not meta_outer:
        print("Falha ao decifrar metadados com a autenticação do volume falso!")
        input("\nPressione Enter para continuar...")
        return
    if not os.path.exists(meta_inner_path):
        print("Este arquivo não é um volume oculto!")
        input("\nPressione Enter para continuar...")
        return
    if 'real_key_file_hash' in meta_outer:
        print("Arquivo-chave detectado para o volume real.")
        if not validate_key_file(meta_outer['real_key_file_hash']):
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

    hidden_falso_length   = meta_outer['hidden_falso_length']
    hidden_padding_length = meta_outer['hidden_padding_length']
    hidden_real_length    = meta_outer['hidden_real_length']

    print("\nDigite o token efêmero para acesso ao volume real:")
    token = getpass.getpass("> ")
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    print("\nAutentique o volume real para descriptografar a parte real (senha + opcional arquivo-chave):")
    pwd_real, _ = choose_auth_method()

    meta_inner = decrypt_meta_json(meta_inner_path, pwd_real)
    if not meta_inner:
        print("Falha ao decifrar metadados do volume real!")
        input("\nPressione Enter para continuar...")
        return

    if token_hash != meta_inner.get('hidden_token_hash'):
        print("Token incorreto!")
        input("\nPressione Enter para continuar...")
        return

    start_real = hidden_falso_length + hidden_padding_length
    end_real = start_real + hidden_real_length
    real_cipher  = combined_data[start_real:end_real]

    argon_params_real = {
        'time_cost': meta_inner['real_argon2_time_cost'],
        'memory_cost': meta_inner['real_argon2_memory_cost'],
        'parallelism': meta_inner['real_argon2_parallelism']
    }
    real_salt_b64 = meta_inner['real_salt']
    real_nonce_b64 = meta_inner['real_nonce']

    attempts = 0
    real_plain_data = None
    while attempts < MAX_ATTEMPTS:
        enc_dict = {
            'ciphertext': real_cipher,
            'nonce': real_nonce_b64,
            'salt': real_salt_b64,
            'argon2_time_cost': argon_params_real["time_cost"],
            'argon2_memory_cost': argon_params_real["memory_cost"],
            'argon2_parallelism': argon_params_real["parallelism"]
        }
        try:
            real_plain_data = decrypt_data_raw_chacha(enc_dict, pwd_real, extra=token.encode())
            break
        except InvalidTag:
            attempts += 1
            print("Falha na descriptografia da parte real (autenticação incorreta)!")
            if attempts >= MAX_ATTEMPTS:
                print("Muitas tentativas! Abortando.")
                input("\nPressione Enter para continuar...")
                return
            else:
                time.sleep(2 ** attempts)
                print("Tente novamente:")
    if real_plain_data is None:
        return

    print("\nParte real decifrada com sucesso. Agora defina a NOVA autenticação para o volume real:")
    pwd_real_new, key_file_hash_new = choose_auth_method()
    argon_params_new_real = get_argon2_parameters_for_encryption()

    enc_real_dict_new = encrypt_data_raw_chacha(real_plain_data, pwd_real_new, argon_params_new_real, extra=token.encode())
    new_real_cipher = enc_real_dict_new['ciphertext']

    # Atualiza o conteúdo combinado mantendo o volume falso e o padding inalterados
    combined_new = combined_data[:hidden_falso_length + hidden_padding_length] + new_real_cipher
    combined_new_rs = rs_encode_data(combined_new)

    meta_inner['real_salt']              = enc_real_dict_new['salt']
    meta_inner['real_nonce']             = enc_real_dict_new['nonce']
    meta_inner['real_argon2_time_cost']  = enc_real_dict_new['argon2_time_cost']
    meta_inner['real_argon2_memory_cost'] = enc_real_dict_new['argon2_memory_cost']
    meta_inner['real_argon2_parallelism'] = enc_real_dict_new['argon2_parallelism']

    if key_file_hash_new:
        meta_inner['real_key_file_hash'] = key_file_hash_new
    else:
        meta_inner.pop('real_key_file_hash', None)

    with open(file_path, 'wb') as f:
        f.write(combined_new_rs)

    encrypt_meta_json(meta_inner_path, meta_inner, pwd_real_new)

    print("\nSenha do volume real atualizada com sucesso!")
    input("\nPressione Enter para continuar...")
