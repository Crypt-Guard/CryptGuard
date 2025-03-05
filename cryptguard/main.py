# main.py

import os
import time
import tempfile
import zipfile

from password_utils import choose_auth_method
from single_shot import encrypt_data_single, decrypt_data_single
from streaming import encrypt_data_streaming, decrypt_data_streaming, STREAMING_THRESHOLD
from hidden_volume import encrypt_hidden_volume, decrypt_file
from utils import clear_screen, generate_ephemeral_token, generate_unique_filename
from config import CHUNK_SIZE, MAX_ATTEMPTS

def list_encrypted_files():
    """
    Retorna a lista de arquivos .enc existentes em ~/Documents/Encoded_files_folder
    """
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    if not os.path.exists(folder):
        return []
    return [f for f in os.listdir(folder) if f.endswith('.enc')]


def ask_chunk_size():
    """
    Permite ao usuário definir chunk_size dinamicamente para streaming.
    Retorna um inteiro. Se inválido ou vazio, retorna CHUNK_SIZE padrão.
    """
    default_cs = CHUNK_SIZE
    print(f"O chunk size padrão é {default_cs} bytes.")
    user_input = input("Digite um novo chunk size (ou ENTER para manter padrão): ").strip()
    if not user_input:
        return default_cs
    try:
        new_size = int(user_input)
        if new_size < 1024:
            print("Valor muito pequeno, forçando 1024.")
            return 1024
        return new_size
    except ValueError:
        print("Entrada inválida, usando chunk size padrão.")
        return default_cs


def encrypt_text():
    """
    Pede ao usuário uma mensagem, escolhe método de auth e criptografa single-shot.
    """
    clear_screen()
    print("=== CRIPTOGRAFAR TEXTO ===")
    message = input("Digite a mensagem: ").encode('utf-8')

    # Pergunta método de autenticação
    combined_pwd, key_file_hash = choose_auth_method()

    encrypt_data_single(message, combined_pwd, "text", ".txt", key_file_hash)
    input("\nPressione Enter para continuar...")


def encrypt_file(file_type: str):
    """
    Criptografa um único arquivo (imagem, PDF, áudio, etc.),
    perguntando sempre o método de auth e chunk size se streaming.
    """
    clear_screen()
    print(f"=== CRIPTOGRAFAR {file_type.upper()} ===")
    file_path = os.path.normpath(input("Caminho do arquivo: ").strip())
    if not os.path.exists(file_path):
        print("Arquivo não encontrado!")
        input("\nPressione Enter para continuar...")
        return

    combined_pwd, key_file_hash = choose_auth_method()

    ext = os.path.splitext(file_path)[1]
    file_size = os.path.getsize(file_path)
    if file_size > STREAMING_THRESHOLD:
        print("\nArquivo grande detectado => modo streaming.\n")
        chunk_size = ask_chunk_size()
        encrypt_data_streaming(file_path, combined_pwd, file_type.lower(), ext,
                               key_file_hash, chunk_size=chunk_size)
    else:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        encrypt_data_single(file_data, combined_pwd, file_type.lower(), ext, key_file_hash)

    input("\nPressione Enter para continuar...")


def encrypt_multiple_files():
    """
    Faz zip de múltiplos arquivos e depois criptografa (single-shot ou streaming).
    """
    clear_screen()
    print("=== CRIPTOGRAFAR MÚLTIPLOS ARQUIVOS ===")
    files = []
    while True:
        file_path = os.path.normpath(input("Caminho do arquivo (deixe em branco para terminar): ").strip())
        if file_path == "":
            break
        if not os.path.exists(file_path):
            print("Arquivo não encontrado! Tente novamente.")
        else:
            files.append(file_path)

    if not files:
        print("Nenhum arquivo selecionado!")
        input("\nPressione Enter para continuar...")
        return

    temp_zip = None
    try:
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
        temp_zip_name = temp_zip.name
        temp_zip.close()

        with zipfile.ZipFile(temp_zip_name, 'w') as zipf:
            for f in files:
                zipf.write(f, arcname=os.path.basename(f))

        combined_pwd, key_file_hash = choose_auth_method()

        zip_size = os.path.getsize(temp_zip_name)
        if zip_size > STREAMING_THRESHOLD:
            print("\nArquivo grande detectado => modo streaming.\n")
            chunk_size = ask_chunk_size()
            encrypt_data_streaming(temp_zip_name, combined_pwd, "multi", ".zip", key_file_hash,
                                   chunk_size=chunk_size)
        else:
            with open(temp_zip_name, 'rb') as f:
                zip_data = f.read()
            encrypt_data_single(zip_data, combined_pwd, "multi", ".zip", key_file_hash)

    finally:
        if temp_zip is not None and os.path.exists(temp_zip_name):
            try:
                os.remove(temp_zip_name)
            except Exception:
                pass

    input("\nPressione Enter para continuar...")


def decrypt_menu():
    """
    Lista arquivos .enc disponíveis e faz descriptografia.
    """
    clear_screen()
    print("=== DESCRIPTOGRAFAR ARQUIVO ===")
    files = list_encrypted_files()
    if not files:
        print("Nenhum arquivo criptografado encontrado!")
        input("\nPressione Enter para voltar...")
        return

    print("\nArquivos disponíveis:")
    for i, f in enumerate(files, 1):
        print(f"[{i}] {f}")

    try:
        choice = int(input("\nEscolha o arquivo: ")) - 1
        selected_file = files[choice]
    except Exception:
        print("Seleção inválida!")
        input("\nPressione Enter para continuar...")
        return

    print("\nEscolha o método de autenticação para descriptografar:")
    combined_pwd, _ = choose_auth_method()

    decrypt_file(selected_file, combined_pwd)

def reencrypt_file():
    """
    Key Rolling / Re-encryption:
    - Escolhe um arquivo .enc existente
    - Pede a senha antiga para descriptografar
    - Cria um arquivo "decrypted_<tipo>_...<ext>" (se for .txt, .jpg, etc.)
    - Pede a nova senha e recriptografa
    - Opcionalmente apaga o antigo e o decifrado
    """
    clear_screen()
    print("=== RE-ENCRYPT (KEY ROLLING) ===")
    files = list_encrypted_files()
    if not files:
        print("Nenhum arquivo criptografado encontrado!")
        input("\nPressione Enter para voltar...")
        return

    print("\nArquivos disponíveis:")
    for i, f in enumerate(files, 1):
        print(f"[{i}] {f}")

    try:
        choice = int(input("\nEscolha o arquivo para re-encriptar: ")) - 1
        selected_file = files[choice]
    except Exception:
        print("Seleção inválida!")
        input("\nPressione Enter para continuar...")
        return

    print(f"\nPrimeiro, será usada a senha antiga para descriptografar {selected_file}.")
    old_pwd, _ = choose_auth_method()

    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    enc_path = os.path.join(folder, selected_file)

    # Lê metadados e verifica se é streaming ou single-shot
    from metadata import decrypt_meta_json
    meta_plain = decrypt_meta_json(enc_path + ".meta", old_pwd)
    if not meta_plain:
        print("Falha ao decifrar metadados (senha incorreta ou corrompidos)!")
        input("\nPressione Enter para continuar...")
        return

    volume_type = meta_plain.get("volume_type", "normal")
    if volume_type == "hidden":
        print("Re-encrypt não suportado para volume oculto neste exemplo.")
        input("\nPressione Enter para continuar...")
        return

    streaming = meta_plain.get("streaming", False)

    # 1) Descriptografar (isso já criará um arquivo com a extensão correta)
    print("\nDescriptografando com a senha antiga ...")
    if streaming:
        decrypt_data_streaming(enc_path, old_pwd)
    else:
        decrypt_data_single(enc_path, old_pwd)

    # Pega a lista de arquivos "decrypted_..." no folder e localiza o + recente
    newly_created = [f for f in os.listdir(folder) if f.startswith("decrypted_")]
    if not newly_created:
        print("Não foi possível encontrar o arquivo decifrado!")
        input("\nPressione Enter para continuar...")
        return

    newly_created_paths = [os.path.join(folder, nf) for nf in newly_created]
    newest = max(newly_created_paths, key=os.path.getmtime)
    print(f"Arquivo decifrado detectado: {os.path.basename(newest)}")

    # 2) Pedir nova senha para recriptografia
    print("\nDigite a NOVA senha (ou método de autenticação) para recriptografar este arquivo:")
    new_pwd, key_file_hash_new = choose_auth_method()

    # 3) Perguntar se quer single-shot ou streaming
    print("\nEscolher modo de recriptografia:")
    print("[1] Single-Shot")
    print("[2] Streaming")
    mode_choice = input("Opção: ").strip()
    mode_streaming = (mode_choice == '2')

    # 4) Re-criptografar. Pega a extensão do 'newest' se quiser manter,
    # mas no meta chamaremos de "reenc" e a "original_ext" será a do arquivo decifrado.
    # Exemplo: Se 'newest' for "... .txt", a 'original_ext' = ".txt"
    _, ext = os.path.splitext(newest)

    if mode_streaming:
        chunk_size = ask_chunk_size()
        encrypt_data_streaming(newest, new_pwd, "reenc", ext, key_file_hash_new, chunk_size=chunk_size)
    else:
        with open(newest, 'rb') as f:
            data_in = f.read()
        encrypt_data_single(data_in, new_pwd, "reenc", ext, key_file_hash_new)

    # 5) Perguntar se quer apagar o arquivo antigo e o decifrado
    remove_old = input("\nDeseja remover o arquivo .enc antigo? (s/n): ").strip().lower()
    if remove_old == 's':
        try:
            os.remove(enc_path)
            os.remove(enc_path + ".meta")
            print("Arquivo antigo removido.")
        except:
            print("Não foi possível remover o arquivo antigo.")

    remove_decrypted = input("Deseja remover o arquivo decifrado? (s/n): ").strip().lower()
    if remove_decrypted == 's':
        try:
            os.remove(newest)
            print("Arquivo decifrado removido.")
        except:
            print("Não foi possível remover o arquivo decifrado.")

    input("\nKey rolling concluído. Pressione Enter para continuar...")

def generate_ephemeral_token_menu():
    """
    Gera um token efêmero em hex (para uso no volume oculto, por exemplo).
    """
    clear_screen()
    print("=== GERAR TOKEN EFÊMERO ===")
    token = generate_ephemeral_token(128)
    print(f"Token gerado (use para volumes ocultos, etc.): {token}")
    input("\nPressione Enter para continuar...")


def main_menu():
    """
    Menu principal do CryptGuard.
    """
    while True:
        clear_screen()
        print("\n=== CRYPTGUARD - SISTEMA DE CRIPTOGRAFIA AVANÇADO ===")
        print("""
[1] Criptografar Texto
[2] Criptografar Arquivo (Imagem/PDF/Áudio)
[3] Descriptografar Arquivo
[4] Criptografar Múltiplos Arquivos
[5] Gerar Token Efêmero
[6] Criar Volume Oculto (Negação Plausível)
[7] Re-Encrypt (Key Rolling) - (para volumes normais)
[8] Trocar Senha do Volume Real (Hidden)
[0] Sair
        """)
        choice = input("Escolha uma opção: ").strip()
        if choice == '1':
            encrypt_text()
        elif choice == '2':
            clear_screen()
            print("Tipo de Arquivo:")
            print("[1] Imagem")
            print("[2] PDF")
            print("[3] Áudio")
            file_choice = input("Escolha: ").strip()
            file_types = {'1': 'image', '2': 'pdf', '3': 'audio'}
            encrypt_file(file_types.get(file_choice, 'file'))
        elif choice == '3':
            decrypt_menu()
        elif choice == '4':
            encrypt_multiple_files()
        elif choice == '5':
            generate_ephemeral_token_menu()
        elif choice == '6':
            encrypt_hidden_volume()
        elif choice == '7':
            reencrypt_file()
        elif choice == '8':
            from hidden_volume import change_real_volume_password
            change_real_volume_password()
        elif choice == '0':
            print("Encerrando...")
            time.sleep(1)
            break
        else:
            print("Opção inválida!")
            time.sleep(1)


if __name__ == "__main__":
    main_menu()
