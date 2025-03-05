# password_utils.py

import os
import sys
import hashlib
import string
import getpass

try:
    from zxcvbn import zxcvbn
except ImportError:
    print("Instale zxcvbn-python: pip install zxcvbn-python")
    sys.exit(1)


def validate_password(pwd: str) -> bool:
    """
    Exige senha >=8 chars, com maiúscula, minúscula, dígito e caractere especial,
    e zxcvbn score >= 3.
    """
    if len(pwd) < 8:
        print("Senha deve ter pelo menos 8 caracteres.")
        return False
    if not any(c.islower() for c in pwd):
        print("Senha deve conter pelo menos uma letra minúscula.")
        return False
    if not any(c.isupper() for c in pwd):
        print("Senha deve conter pelo menos uma letra maiúscula.")
        return False
    if not any(c.isdigit() for c in pwd):
        print("Senha deve conter pelo menos um dígito.")
        return False
    if not any(c in string.punctuation for c in pwd):
        print("Senha deve conter pelo menos um caractere especial.")
        return False

    score = zxcvbn(pwd)['score']
    if score < 3:
        print("Senha fraca. Tente uma senha mais complexa.")
        return False
    return True


def get_file_hash(file_path):
    """
    Retorna (bytes_digest, hexdigest).
    """
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as file:
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.digest(), hasher.hexdigest()
    except Exception:
        print("Erro ao ler o arquivo-chave.")
        return None, None


def validate_key_file(expected_hash: str) -> bool:
    """
    Pergunta caminho do arquivo-chave e compara SHA-256.
    """
    key_file_path = os.path.normpath(input("Digite o caminho do arquivo-chave para validação: ").strip())
    if not os.path.exists(key_file_path):
        print("Arquivo-chave não encontrado!")
        return False
    with open(key_file_path, 'rb') as f:
        data = f.read()
    computed_hash = hashlib.sha256(data).hexdigest()
    if computed_hash != expected_hash:
        print("Arquivo-chave inválido!")
        return False
    return True


def get_combined_password():
    """
    Solicita senha (dupla verificação) + (opcional) arquivo-chave.
    Retorna (combined, key_file_hash).
    """
    while True:
        pwd1 = getpass.getpass("Digite a senha: ")
        if not validate_password(pwd1):
            print("Senha fraca ou inválida, tente novamente.")
            continue

        pwd2 = getpass.getpass("Confirme a senha: ")
        if pwd1 != pwd2:
            print("As senhas não conferem, tente novamente.")
            continue
        break

    password_bytes = bytearray(pwd1.encode())

    use_key_file = input("Deseja usar um arquivo-chave? (s/n): ").strip().lower()
    key_file_bytes = bytearray()
    key_file_hash = None
    if use_key_file == 's':
        key_file_path = os.path.normpath(input("Caminho do arquivo-chave: ").strip())
        if os.path.exists(key_file_path):
            key_file_digest, key_file_hash = get_file_hash(key_file_path)
            if key_file_digest is not None:
                key_file_bytes = bytearray(key_file_digest)
            else:
                print("Erro ao processar o arquivo-chave. Usando apenas a senha.")
        else:
            print("Arquivo-chave não encontrado. Usando apenas a senha.")

    combined = password_bytes + key_file_bytes

    pwd1 = "0" * len(pwd1)
    pwd2 = "0" * len(pwd2)
    for i in range(len(password_bytes)):
        password_bytes[i] = 0
    for i in range(len(key_file_bytes)):
        key_file_bytes[i] = 0

    return combined, key_file_hash


def get_single_password():
    """
    Somente senha (sem arquivo-chave).
    """
    while True:
        pwd1 = getpass.getpass("Digite a senha (somente senha): ")
        if not validate_password(pwd1):
            print("Senha fraca ou inválida, tente novamente.")
            continue

        pwd2 = getpass.getpass("Confirme a senha: ")
        if pwd1 != pwd2:
            print("As senhas não conferem, tente novamente.")
            continue
        break

    password_bytes = bytearray(pwd1.encode())
    pwd1 = "0" * len(pwd1)
    pwd2 = "0" * len(pwd2)
    return password_bytes


def choose_auth_method():
    """
    Duas opções: 
    [1] Senha + arquivo-chave
    [2] Somente senha
    """
    print("\nSelecione o método de autenticação:")
    print("[1] Senha + arquivo-chave")
    print("[2] Somente Senha (sem arquivo-chave)")
    choice = input("Escolha: ").strip()

    if choice == '1':
        return get_combined_password()
    elif choice == '2':
        pwd = get_single_password()
        return pwd, None
    else:
        print("Opção inválida, usando modo padrão (senha + arquivo-chave).")
        return get_combined_password()
