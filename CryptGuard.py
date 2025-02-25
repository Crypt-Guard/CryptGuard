import os
import sys
import json
import base64
import secrets
import time
import datetime
import tempfile
import zipfile
import struct
import hashlib
import string
import subprocess
import random
from typing import Optional, Tuple

# Bibliotecas externas
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type
from reedsolo import RSCodec

# Inicializa Reed-Solomon com 32 bytes de paridade (máximo de dados por bloco ≈ 223 bytes)
rs = RSCodec(32)

try:
    from zxcvbn import zxcvbn
except ImportError:
    print("Instale zxcvbn-python: pip install zxcvbn-python")
    sys.exit(1)

# =============================================================================
# CONFIGURAÇÕES GERAIS
# =============================================================================

# -- Parâmetros default para Argon2id do arquivo --
DEFAULT_ARGON_PARAMS = {"time_cost": 4, "memory_cost": 102400, "parallelism": 2}

# -- Parâmetros fixos (ou simples) para cifrar METADADOS --
META_ARGON_PARAMS = {
    "time_cost": 2,      # pode ajustar
    "memory_cost": 65536,  # pode ajustar
    "parallelism": 2,
}
META_SALT_SIZE = 16  # bytes do "meta_salt"

# Para streaming
CHUNK_SIZE = 1024 * 1024          # 1 MB
STREAMING_THRESHOLD = 10 * 1024 * 1024  # 10 MB

# Inicia Reed-Solomon com 32 bytes de paridade
rs = RSCodec(32)

# Número máximo de tentativas (brute force)
MAX_ATTEMPTS = 5

# =============================================================================
# FUNÇÕES DE AJUDA (KDF, ENTROPIA, etc.)
# =============================================================================

def generate_key_from_password(password: bytes, salt: bytes, params: dict) -> bytes:
    """
    Deriva 32 bytes usando Argon2id, retornando-os *crus* (não base64).
    """
    key = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"],
        hash_len=32,
        type=Type.ID
    )
    return key

def get_argon2_parameters_for_encryption():
    """
    Pergunta ao usuário se deseja customizar Argon2id. Retorna dict (time_cost, memory_cost, parallelism).
    """
    default_params = {"time_cost": 4, "memory_cost": 102400, "parallelism": 2}
    custom = input("Deseja customizar os parâmetros de Argon2id? (s/n): ").strip().lower()
    if custom != 's':
        return default_params
    while True:
        try:
            time_cost = int(input("Digite time_cost (mínimo 3, padrão 4): "))
            memory_cost = int(input("Digite memory_cost em KiB (mínimo 65536, padrão 102400): "))
            parallelism = int(input("Digite parallelism (mínimo 2, padrão 2): "))

            if time_cost < 3:
                time_cost = 3
            if memory_cost < 65536:
                memory_cost = 102400
            if parallelism < 2:
                parallelism = 2

            return {"time_cost": time_cost, "memory_cost": memory_cost, "parallelism": parallelism}
        except ValueError:
            print("Entrada inválida! Por favor, insira apenas números inteiros.")

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
    """Hash SHA-256 incremental de um arquivo para uso como 'arquivo-chave'."""
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
    Pergunta caminho do arquivo-chave e compara SHA-256 com expected_hash.
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
    Solicita senha + (opcional) arquivo-chave, concatena ambos. Retorna (combined, key_file_hash).
    """
    pwd = input("Digite a senha: ")
    while not validate_password(pwd):
        print("Senha fraca! Escolha outra.")
        pwd = input("Digite a senha: ")
    
    password_bytes = pwd.encode()
    try:
        use_key_file = input("Deseja usar um arquivo-chave? (s/n): ").strip().lower()
        key_file_bytes, key_file_hash = (b"", None)
        if use_key_file == 's':
            key_file_path = os.path.normpath(input("Caminho do arquivo-chave: ").strip())
            if os.path.exists(key_file_path):
                key_file_bytes, key_file_hash = get_file_hash(key_file_path)
                if key_file_bytes is None:
                    key_file_bytes, key_file_hash = (b"", None)
                    print("Erro ao processar o arquivo-chave. Usando apenas senha.")
            else:
                print("Arquivo-chave não encontrado. Usando apenas a senha.")
        combined = password_bytes + key_file_bytes
    finally:
        # Tentativa de wipe da senha (não garante 100% em Python)
        password_bytes = b'\x00' * len(password_bytes)
    return combined, key_file_hash

# =============================================================================
# CRIPTOGRAFIA DE METADADOS (cifrar JSON de salt e params)
# =============================================================================

def encrypt_meta_json(meta_path: str, meta_plain: dict, user_password: bytes):
    """
    Cifra (meta_plain) em JSON, salvando no .meta apenas meta_salt, meta_nonce, meta_ciphertext.
    """
    meta_salt = secrets.token_bytes(META_SALT_SIZE)  # para derivar metaKey
    meta_key = generate_key_from_password(user_password, meta_salt, META_ARGON_PARAMS)
    cipher = ChaCha20Poly1305(meta_key)

    meta_nonce = secrets.token_bytes(12)
    meta_json_str = json.dumps(meta_plain, sort_keys=True)
    meta_cipher = cipher.encrypt(meta_nonce, meta_json_str.encode(), None)

    meta_dict = {
        "meta_salt": base64.b64encode(meta_salt).decode(),
        "meta_nonce": base64.b64encode(meta_nonce).decode(),
        "meta_ciphertext": base64.b64encode(meta_cipher).decode()
    }
    with open(meta_path, 'w') as f:
        json.dump(meta_dict, f)

def decrypt_meta_json(meta_path: str, user_password: bytes) -> Optional[dict]:
    """
    Lê meta_salt, meta_nonce, meta_ciphertext do .meta; decifra e retorna o dicionário.
    Se falhar, retorna None.
    """
    if not os.path.exists(meta_path):
        return None
    with open(meta_path, 'r') as f:
        meta_dict = json.load(f)
    meta_salt = base64.b64decode(meta_dict["meta_salt"])
    meta_nonce = base64.b64decode(meta_dict["meta_nonce"])
    meta_cipher = base64.b64decode(meta_dict["meta_ciphertext"])

    meta_key = generate_key_from_password(user_password, meta_salt, META_ARGON_PARAMS)
    cipher = ChaCha20Poly1305(meta_key)
    try:
        meta_json_str = cipher.decrypt(meta_nonce, meta_cipher, None)
        return json.loads(meta_json_str.decode())
    except InvalidTag:
        return None

# =============================================================================
# FUNÇÕES DE REED-SOLOMON
# =============================================================================
def rs_encode_data(data: bytes, block_size=223) -> bytes:
    """
    Divide 'data' em blocos <= block_size e aplica Reed-Solomon. Retorna header + blocos codificados.
    """
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    encoded_blocks = [rs.encode(block) for block in blocks]
    header = struct.pack('>I', len(encoded_blocks))
    for block in encoded_blocks:
        header += struct.pack('>H', len(block))
    return header + b''.join(encoded_blocks)

def rs_decode_data(data: bytes) -> bytes:
    """
    Decodifica o que foi gerado por rs_encode_data.
    """
    if len(data) < 4:
        raise ValueError("Dados RS incompletos.")
    num_blocks = struct.unpack('>I', data[:4])[0]
    offset = 4
    block_lengths = []
    for _ in range(num_blocks):
        if offset + 2 > len(data):
            raise ValueError("Header RS incompleto.")
        length = struct.unpack('>H', data[offset:offset+2])[0]
        block_lengths.append(length)
        offset += 2
    decoded = b""
    for length in block_lengths:
        block = data[offset:offset+length]
        offset += length
        decoded += rs.decode(block)[0]
    return decoded

# =============================================================================
# ENCRYPT/DECRYPT (Single-Shot e Streaming) c/ AAD
# =============================================================================

def encrypt_chunk(chunk: bytes, key: bytes, aad: bytes, chunk_index: int) -> bytes:
    """
    Criptografa 1 chunk com ChaCha20Poly1305.
    - Nonce = 12 bytes com secrets.token_bytes()
    - AAD = (aad + b"|chunk_index=xxx")
    - Aplica RS no final.
    """
    cipher = ChaCha20Poly1305(key)
    nonce = secrets.token_bytes(12)

    full_aad = aad + b"|chunk_index=%d" % chunk_index

    enc_chunk = cipher.encrypt(nonce, chunk, full_aad)
    checksum = hashlib.sha256(chunk).digest()  # 32 bytes

    raw_block = nonce + struct.pack('>I', len(enc_chunk)) + enc_chunk + checksum
    rs_block = rs_encode_data(raw_block)
    block_len = struct.pack('>I', len(rs_block))
    return block_len + rs_block

def decrypt_chunk(data: bytes, key: bytes, offset: int, aad: bytes, chunk_index: int) -> Tuple[Optional[bytes], int]:
    """
    Lê 4 bytes -> block_len, em seguida block_len de RS block.
    Decodifica e extrai [nonce(12), enc_len(4), ciphertext, checksum(32)].
    Tenta decrypt com AAD = (aad + "|chunk_index=xxx").
    Se der certo, retorna (plaintext, novo_offset). Caso contrário, retorna (None, offset).
    """
    if offset + 4 > len(data):
        return None, offset
    block_len = struct.unpack('>I', data[offset:offset+4])[0]
    offset += 4
    if offset + block_len > len(data):
        return None, offset

    rs_block = data[offset:offset+block_len]
    offset += block_len

    try:
        raw_block = rs_decode_data(rs_block)
    except Exception:
        print("Erro na decodificação RS!")
        return None, offset

    nonce = raw_block[:12]
    enc_len = struct.unpack('>I', raw_block[12:16])[0]
    ciphertext = raw_block[16:16+enc_len]
    checksum_stored = raw_block[16+enc_len:16+enc_len+32]

    cipher = ChaCha20Poly1305(key)
    full_aad = aad + b"|chunk_index=%d" % chunk_index

    try:
        plaintext = cipher.decrypt(nonce, ciphertext, full_aad)
    except InvalidTag:
        print("Falha na descriptografia de um chunk (InvalidTag).")
        return None, offset

    # Confere checksum
    if hashlib.sha256(plaintext).digest() != checksum_stored:
        print("Checksum do chunk não confere!")
        return None, offset

    return plaintext, offset

# SINGLE-SHOT = 1 chunk
def encrypt_data_single(data: bytes, password: bytes, file_type: str, original_ext: str = "", key_file_hash: str = None):
    """
    Usa Argon2 p/ derivar chave do arquivo, criptografa em 1 chunk, com AAD, e
    salva RS-coded result. Depois, salva metadata (salt, argon params etc.) CIFRADO.
    """
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    os.makedirs(folder, exist_ok=True)

    argon_params = get_argon2_parameters_for_encryption()
    file_salt = secrets.token_bytes(32)  # Salt do ARQUIVO
    derived_key = generate_key_from_password(password, file_salt, argon_params)

    # AAD base
    # Exemplo de JSON textual -> bytes. Pode adicionar mais coisas se quiser.
    aad_base = json.dumps({
        "file_type": file_type,
        "original_ext": original_ext,
        "volume_type": "normal"
    }, sort_keys=True).encode()

    # Criptografa em "1 chunk" com chunk_index=0
    chunk_index = 0
    enc_data = encrypt_chunk(data, derived_key, aad_base, chunk_index)

    filename = generate_unique_filename(file_type)
    enc_path = os.path.join(folder, filename)
    with open(enc_path, 'wb') as f:
        f.write(enc_data)

    # Monta o metadado "real" do arquivo, a ser cifrado
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

    # Cifrar e escrever .meta
    encrypt_meta_json(enc_path + ".meta", meta_plain, password)

    print(f"\nArquivo criptografado salvo como: {filename}")

def decrypt_data_single(enc_path: str, password: bytes):
    """
    Lê .meta, decifra para obter salt e params. Lê o arquivo, decodifica RS,
    extrai chunk, decripta com AAD (chunk_index=0).
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

    # AAD base
    aad_base = json.dumps({
        "file_type": meta_plain["file_type"],
        "original_ext": meta_plain["original_ext"],
        "volume_type": meta_plain["volume_type"]
    }, sort_keys=True).encode()

    # Lê o arquivo
    with open(enc_path, 'rb') as f:
        file_data = f.read()

    # 1 chunk => chunk_index=0
    plaintext, _ = decrypt_chunk(file_data, derived_key, 0, aad_base, 0)
    if plaintext is None:
        print("Falha na descriptografia do arquivo!")
        return

    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    out_name = f"decrypted_{meta_plain['file_type']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}{meta_plain.get('original_ext','')}"
    out_path = os.path.join(folder, out_name)
    with open(out_path, 'wb') as f:
        f.write(plaintext)

    print(f"\nArquivo descriptografado salvo como: {out_name}")

# STREAMING

def encrypt_data_streaming(file_path: str, password: bytes, file_type: str, original_ext: str = "", key_file_hash: str = None):
    """
    Criptografa arquivo grande, chunk a chunk, cada chunk com AAD (contendo file_type, etc.),
    + chunk_index. Armazena RS-coded result concatenado.
    """
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    os.makedirs(folder, exist_ok=True)

    argon_params = get_argon2_parameters_for_encryption()
    file_salt = secrets.token_bytes(32)
    derived_key = generate_key_from_password(password, file_salt, argon_params)

    # AAD base
    aad_dict = {
        "file_type": file_type,
        "original_ext": original_ext,
        "volume_type": "normal"
    }
    aad_base = json.dumps(aad_dict, sort_keys=True).encode()

    filename = generate_unique_filename(file_type)
    enc_path = os.path.join(folder, filename)

    file_size = os.path.getsize(file_path)
    processed = 0

    with open(file_path, 'rb') as fin, open(enc_path, 'wb') as fout:
        chunk_index = 0
        while True:
            chunk = fin.read(CHUNK_SIZE)
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

    # Meta do arquivo
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
        "total_encrypted_bytes": os.path.getsize(enc_path)
    }
    if key_file_hash:
        meta_plain["key_file_hash"] = key_file_hash

    encrypt_meta_json(enc_path + ".meta", meta_plain, password)
    return enc_path

def decrypt_data_streaming(enc_path: str, password: bytes):
    """
    Lê .meta cifrado, obtém salt e params. Decifra chunk a chunk, usando AAD base + chunk_index.
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

    aad_dict = {
        "file_type": meta_plain["file_type"],
        "original_ext": meta_plain["original_ext"],
        "volume_type": meta_plain["volume_type"]
    }
    aad_base = json.dumps(aad_dict, sort_keys=True).encode()

    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    out_name = f"decrypted_{meta_plain['file_type']}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}{meta_plain.get('original_ext','')}"
    out_path = os.path.join(folder, out_name)

    with open(enc_path, 'rb') as fin, open(out_path, 'wb') as fout:
        data = fin.read()
        offset = 0
        chunk_index = 0
        while offset < len(data):
            plaintext, offset = decrypt_chunk(data, derived_key, offset, aad_base, chunk_index)
            if plaintext is None:
                print("Falha em um chunk!")
                break
            fout.write(plaintext)
            chunk_index += 1

    print(f"\nArquivo descriptografado salvo como: {out_name}")

# =============================================================================
# VOLUME OCULTO (EXEMPLO)
# =============================================================================

def encrypt_data_raw_chacha(data: bytes, password: bytes, argon_params: dict) -> dict:
    """
    Criptografa 'data' (single-shot) SEM RS, retornando dict com {ciphertext, nonce, salt, ...}.
    Aqui substituímos XChaCha20Poly1305 por ChaCha20Poly1305 com nonce=12 bytes.
    """
    salt = secrets.token_bytes(32)
    key = generate_key_from_password(password, salt, argon_params)
    cipher = ChaCha20Poly1305(key)
    nonce = secrets.token_bytes(12)
    ciphertext = cipher.encrypt(nonce, data, None)
    return {
        'ciphertext': ciphertext,
        'nonce': base64.b64encode(nonce).decode(),
        'salt': base64.b64encode(salt).decode(),
        'argon2_time_cost': argon_params["time_cost"],
        'argon2_memory_cost': argon_params["memory_cost"],
        'argon2_parallelism': argon_params["parallelism"]
    }

def decrypt_data_raw_chacha(enc_dict: dict, password: bytes) -> bytes:
    """
    Inverso de encrypt_data_raw_chacha.
    """
    salt = base64.b64decode(enc_dict['salt'])
    argon_params = {
        'time_cost': enc_dict['argon2_time_cost'],
        'memory_cost': enc_dict['argon2_memory_cost'],
        'parallelism': enc_dict['argon2_parallelism']
    }
    key = generate_key_from_password(password, salt, argon_params)
    cipher = ChaCha20Poly1305(key)
    nonce = base64.b64decode(enc_dict['nonce'])
    ciphertext = enc_dict['ciphertext']
    return cipher.decrypt(nonce, ciphertext, None)

def encrypt_hidden_volume():
    """
    Exemplo de volume oculto: pega 2 arquivos (falso e real), cifra cada um sem RS,
    concatena com padding e APENAS então aplica RS no final.
    Os metadados do volume oculto também são cifrados via meta-salt, para não expor param do volume.
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

    # Criptografa sem RS
    enc_falso_dict = encrypt_data_raw_chacha(data_falso, pwd_falso, argon_params_falso)
    enc_real_dict  = encrypt_data_raw_chacha(data_real, pwd_real, argon_params_real)

    falso_cipher = enc_falso_dict['ciphertext']
    real_cipher = enc_real_dict['ciphertext']

    hidden_falso_length = len(falso_cipher)
    hidden_real_length = len(real_cipher)
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

    # Monta metadados do volume oculto
    meta_plain = {
        'volume_type': "hidden",
        'hidden_falso_length': hidden_falso_length,
        'hidden_padding_length': hidden_padding_length,
        'hidden_real_length': hidden_real_length,
        'falso_nonce': enc_falso_dict['nonce'],
        'real_nonce': enc_real_dict['nonce'],
        'falso_salt': enc_falso_dict['salt'],
        'real_salt': enc_real_dict['salt'],
        'falso_argon2_time_cost': argon_params_falso["time_cost"],
        'falso_argon2_memory_cost': argon_params_falso["memory_cost"],
        'falso_argon2_parallelism': argon_params_falso["parallelism"],
        'real_argon2_time_cost': argon_params_real["time_cost"],
        'real_argon2_memory_cost': argon_params_real["memory_cost"],
        'real_argon2_parallelism': argon_params_real["parallelism"],
        'created_at': datetime.datetime.now().isoformat(),
        'hidden_token_hash': hidden_token_hash
    }
    if key_file_hash_falso:
        meta_plain['falso_key_file_hash'] = key_file_hash_falso
    if key_file_hash_real:
        meta_plain['real_key_file_hash'] = key_file_hash_real

    # Precisamos derivar a metaKey com a senha do volume falso (cover story):
    encrypt_meta_json(hidden_path + ".meta", meta_plain, pwd_falso)

    print("\nVolume oculto criado com sucesso!")
    print(f"Arquivo: {hidden_filename}")
    print(f"Guarde o token efêmero para acesso ao volume real: {hidden_token}")
    input("\nPressione Enter para continuar...")

def decrypt_file(encrypted_file: str, password: bytes):
    """
    Detecta se 'volume_type' é normal ou hidden. Chama a rotina apropriada.
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

        hidden_falso_length = meta_plain['hidden_falso_length']
        hidden_padding_length = meta_plain['hidden_padding_length']
        hidden_real_length = meta_plain['hidden_real_length']

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

        pwd_hidden = input("> ").encode()

        enc_dict = {
            'ciphertext': target_cipher,
            'nonce': nonce_str,
            'salt': salt_str,
            'argon2_time_cost': argon_params_choice["time_cost"],
            'argon2_memory_cost': argon_params_choice["memory_cost"],
            'argon2_parallelism': argon_params_choice["parallelism"]
        }

        attempts = 0
        while attempts < MAX_ATTEMPTS:
            try:
                decrypted_data = decrypt_data_raw_chacha(enc_dict, pwd_hidden)
                break
            except InvalidTag:
                attempts += 1
                print("Falha na descriptografia do volume oculto!")
                if attempts >= MAX_ATTEMPTS:
                    print("Muitas tentativas! Aguarde antes de tentar novamente.")
                    time.sleep(30)
                    input("\nPressione Enter para continuar...")
                    return
                else:
                    time.sleep(2 ** attempts)
                    pwd_hidden = input("Senha incorreta! Digite novamente: ").strip().encode()

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
            # single-shot
            decrypt_data_single(file_path, password)

    input("\nPressione Enter para continuar...")

# =============================================================================
# FUNÇÕES DE MENU (interação)
# =============================================================================

def generate_ephemeral_token(n_bits=128):
    """Retorna um token em hex com n_bits de entropia."""
    num = int.from_bytes(secrets.token_bytes((n_bits+7)//8), 'big')
    return hex(num)[2:]

def gerar_numero_aleatorio(n_bits):
    """Mantido só para eventuais usos em nomes. Usa secrets.token_bytes internamente."""
    # Se preferir, pode usar a mesma lógica do generate_ephemeral_token
    random_bytes = secrets.token_bytes((n_bits+7)//8)
    numero = int.from_bytes(random_bytes, 'big')
    excesso = (len(random_bytes)*8 - n_bits)
    if excesso > 0:
        numero >>= excesso
    return numero

def generate_unique_filename(prefix: str, extension: str = ".enc") -> str:
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    random_component = hex(gerar_numero_aleatorio(64))[2:]
    return f"{prefix}_{timestamp}_{random_component}{extension}"

def list_encrypted_files():
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    if not os.path.exists(folder):
        return []
    return [f for f in os.listdir(folder) if f.endswith('.enc')]

def clear_screen():
    subprocess.call('cls' if os.name == 'nt' else 'clear', shell=True)

def encrypt_text():
    clear_screen()
    print("=== CRIPTOGRAFAR TEXTO ===")
    message = input("Digite a mensagem: ").encode('utf-8')
    print("\nOpção: usar arquivo-chave para aumentar entropia.")
    use_key = input("Deseja usar arquivo-chave? (s/n): ").strip().lower()
    if use_key == 's':
        combined_pwd, key_file_hash = get_combined_password()
    else:
        pwd = input("Digite a senha: ")
        while not validate_password(pwd):
            print("Senha não atende aos requisitos!")
            pwd = input("Digite a senha: ")
        combined_pwd = pwd.encode()
        key_file_hash = None

    encrypt_data_single(message, combined_pwd, "text", ".txt", key_file_hash)
    input("\nPressione Enter para continuar...")

def encrypt_file(file_type: str):
    clear_screen()
    print(f"=== CRIPTOGRAFAR {file_type.upper()} ===")
    file_path = os.path.normpath(input("Caminho do arquivo: ").strip())
    if not os.path.exists(file_path):
        print("Arquivo não encontrado!")
        input("\nPressione Enter para continuar...")
        return

    print("\nOpção: usar arquivo-chave para aumentar entropia.")
    use_key = input("Deseja usar arquivo-chave? (s/n): ").strip().lower()
    if use_key == 's':
        combined_pwd, key_file_hash = get_combined_password()
    else:
        pwd = input("Digite a senha: ")
        while not validate_password(pwd):
            print("Senha não atende aos requisitos!")
            pwd = input("Digite a senha: ")
        combined_pwd = pwd.encode()
        key_file_hash = None

    ext = os.path.splitext(file_path)[1]
    if os.path.getsize(file_path) > STREAMING_THRESHOLD:
        encrypt_data_streaming(file_path, combined_pwd, file_type.lower(), ext, key_file_hash)
    else:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        encrypt_data_single(file_data, combined_pwd, file_type.lower(), ext, key_file_hash)
    input("\nPressione Enter para continuar...")

def encrypt_multiple_files():
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

        print("\nOpção: usar arquivo-chave para aumentar entropia.")
        use_key = input("Deseja usar arquivo-chave? (s/n): ").strip().lower()
        if use_key == 's':
            combined_pwd, key_file_hash = get_combined_password()
        else:
            pwd = input("Digite a senha: ")
            while not validate_password(pwd):
                print("Senha não atende aos requisitos!")
                pwd = input("Digite a senha: ")
            combined_pwd = pwd.encode()
            key_file_hash = None

        if os.path.getsize(temp_zip_name) > STREAMING_THRESHOLD:
            encrypt_data_streaming(temp_zip_name, combined_pwd, "multi", ".zip", key_file_hash)
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

    print("\nOpção: usar arquivo-chave para aumentar entropia (se aplicável).")
    use_key = input("Deseja usar arquivo-chave? (s/n): ").strip().lower()
    if use_key == 's':
        combined_pwd, _ = get_combined_password()
    else:
        pwd = input("Digite a senha: ")
        while not validate_password(pwd):
            print("Senha não atende aos requisitos!")
            pwd = input("Digite a senha: ")
        combined_pwd = pwd.encode()

    decrypt_file(selected_file, combined_pwd)

def generate_ephemeral_token_menu():
    clear_screen()
    print("=== GERAR TOKEN EFÊMERO ===")
    token = generate_ephemeral_token(128)
    print(f"Token gerado (use para volumes ocultos, etc.): {token}")
    input("\nPressione Enter para continuar...")

def main_menu():
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
        elif choice == '0':
            print("Encerrando...")
            time.sleep(1)
            break
        else:
            print("Opção inválida!")
            time.sleep(1)

if __name__ == "__main__":
    main_menu()

