# main.py

import os
import time
import tempfile
import zipfile

from config import CHUNK_SIZE, STREAMING_THRESHOLD, MAX_ATTEMPTS
from password_utils import choose_auth_method
from single_shot import encrypt_data_single, decrypt_data_single
from streaming import encrypt_data_streaming, decrypt_data_streaming
from hidden_volume import encrypt_hidden_volume, decrypt_file, change_real_volume_password
from utils import clear_screen, generate_ephemeral_token, generate_unique_filename
from config import CHUNK_SIZE, MAX_ATTEMPTS

def list_encrypted_files():
    """
    Retorna a lista de arquivos .enc existentes em ~/Documents/Encoded_files_folder.
    Como não é possível identificar com precisão o tipo (normal ou hidden) sem decriptar os metadados,
    a função exibirá apenas os nomes dos arquivos.
    """
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    if not os.path.exists(folder):
        return []
    files = [f for f in os.listdir(folder) if f.endswith('.enc')]
    result = []
    for f in files:
        result.append((f, "??"))
    return result

def ask_chunk_size():
    """
    Permite ao usuário definir chunk_size dinamicamente para streaming.
    Retorna um inteiro. Se inválido ou vazio, retorna o CHUNK_SIZE padrão.
    """
    default_cs = CHUNK_SIZE
    print(f"O chunk size padrão é {default_cs} bytes.")
    user_input = input("Digite um novo chunk size (ou ENTER para manter o padrão): ").strip()
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
    Solicita ao usuário uma mensagem e criptografa em modo single-shot.
    """
    clear_screen()
    print("=== CRIPTOGRAFAR TEXTO ===")
    message = input("Digite a mensagem: ").encode('utf-8')
    combined_pwd, key_file_hash = choose_auth_method()
    encrypt_data_single(message, combined_pwd, "text", ".txt", key_file_hash)
    input("\nPressione Enter para continuar...")

def encrypt_file(file_type: str):
    """
    Criptografa um único arquivo (imagem, PDF, áudio, etc.), utilizando autenticação unificada.
    Se o arquivo for grande, utiliza o modo streaming.
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
        print("\nArquivo grande detectado => usando modo streaming.\n")
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
    Compacta múltiplos arquivos em um zip e então criptografa-o.
    """
    clear_screen()
    print("=== CRIPTOGRAFAR MÚLTIPLOS ARQUIVOS ===")
    files = []
    while True:
        entrada = input("Caminho do arquivo (deixe em branco para terminar): ").strip()
        if entrada == "":
            break
        file_path = os.path.normpath(entrada)
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
            print("\nArquivo grande detectado => usando modo streaming.\n")
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
    Lista os arquivos .enc disponíveis e permite ao usuário selecionar um para descriptografar.
    Para volumes ocultos, será solicitado a autenticação conforme necessário.
    """
    clear_screen()
    print("=== DESCRIPTOGRAFAR ARQUIVO ===")
    files = list_encrypted_files()
    if not files:
        print("Nenhum arquivo criptografado encontrado!")
        input("\nPressione Enter para voltar...")
        return
    print("\nArquivos disponíveis:")
    for i, (f, vol_type) in enumerate(files, 1):
        print(f"[{i}] {f} ({vol_type})")
    try:
        choice = int(input("\nEscolha o arquivo: ")) - 1
        selected_file, _ = files[choice]
    except Exception:
        print("Seleção inválida!")
        input("\nPressione Enter para continuar...")
        return
    print("\nSelecione o método de autenticação para descriptografar:")
    combined_pwd, _ = choose_auth_method()
    # A função decrypt_file usa a senha fornecida sem solicitar novamente.
    decrypt_file(selected_file, combined_pwd)

def reencrypt_file():
    """
    Realiza o processo de Key Rolling (re-encriptação):
      - Descriptografa o arquivo usando a autenticação antiga,
      - Solicita nova autenticação e recriptografa,
      - Opcionalmente remove o arquivo original.
    """
    clear_screen()
    print("=== RE-ENCRYPT (KEY ROLLING) ===")
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    files = [f for f in os.listdir(folder) if f.endswith('.enc')]
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
    print(f"\nUsaremos a autenticação antiga para descriptografar {selected_file}.")
    old_pwd, _ = choose_auth_method()
    enc_path = os.path.join(folder, selected_file)
    from metadata import decrypt_meta_json
    meta_plain = decrypt_meta_json(enc_path + ".meta", old_pwd)
    if not meta_plain:
        print("Falha ao decifrar metadados (autenticação incorreta ou dados corrompidos)!")
        input("\nPressione Enter para continuar...")
        return
    volume_type = meta_plain.get("volume_type", "normal")
    if volume_type == "hidden":
        print("Re-encrypt não suportado para volume oculto neste exemplo.")
        input("\nPressione Enter para continuar...")
        return
    streaming = meta_plain.get("streaming", False)
    print("\nDescriptografando com a autenticação antiga ...")
    if streaming:
        decrypt_data_streaming(enc_path, old_pwd)
    else:
        decrypt_data_single(enc_path, old_pwd)
    folder_files = os.listdir(folder)
    newly_created = [f for f in folder_files if f.startswith("decrypted_")]
    if not newly_created:
        print("Não foi possível encontrar o arquivo decifrado!")
        input("\nPressione Enter para continuar...")
        return
    newly_created_paths = [os.path.join(folder, nf) for nf in newly_created]
    newest = max(newly_created_paths, key=os.path.getmtime)
    print(f"Arquivo decifrado detectado: {os.path.basename(newest)}")
    print("\nDigite a nova autenticação (senha + opcional arquivo-chave) para recriptografar este arquivo:")
    new_pwd, key_file_hash_new = choose_auth_method()
    print("\nEscolha o modo de recriptografia:")
    print("[1] Single-Shot")
    print("[2] Streaming")
    mode_choice = input("Opção: ").strip()
    mode_streaming = (mode_choice == '2')
    _, ext = os.path.splitext(newest)
    if mode_streaming:
        chunk_size = ask_chunk_size()
        encrypt_data_streaming(newest, new_pwd, "reenc", ext, key_file_hash_new, chunk_size=chunk_size)
    else:
        with open(newest, 'rb') as f:
            data_in = f.read()
        encrypt_data_single(data_in, new_pwd, "reenc", ext, key_file_hash_new)
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
    Gera um token efêmero em hex e o exibe ao usuário.
    """
    clear_screen()
    print("=== GERAR TOKEN EFÊMERO ===")
    token = generate_ephemeral_token(128)
    print(f"Token gerado (use para volumes ocultos, etc.): {token}")
    input("\nPressione Enter para continuar...")

def main_menu():
    """
    Menu principal do CryptGuard com melhorias de usabilidade e fluxos de autenticação unificados.
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
