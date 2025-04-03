# hidden_volume.py
"""
Implements hidden volumes with plausible deniability and real volume password changes.
"""

import os
import base64
import datetime
import time
import random
import secrets
import hashlib
import getpass
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from rs_codec import rs_encode_data, rs_decode_data
from argon_utils import generate_key_from_password, get_argon2_parameters_for_encryption
from password_utils import validate_key_file, choose_auth_method
from metadata import encrypt_meta_json, decrypt_meta_json
from utils import generate_unique_filename, generate_ephemeral_token, clear_screen
from single_shot import decrypt_data_single
from streaming import decrypt_data_streaming
from config import MAX_ATTEMPTS, STREAMING_THRESHOLD

def read_file_data(file_path: str) -> bytes:
    with open(file_path, 'rb') as f:
        return f.read()


def encrypt_hidden_volume():
    """
    Creates a hidden volume (real + decoy):
      - Each file set is encrypted, then concatenated with random padding.
      - Reed-Solomon is applied to the combined data.
      - Outer meta is decoy, inner meta is real.
    """
    clear_screen()
    print("=== ENCRYPT HIDDEN VOLUME ===")
    decoy_file = os.path.normpath(input("Enter path for decoy file: ").strip())
    real_file = os.path.normpath(input("Enter path for real file: ").strip())

    if not os.path.exists(decoy_file) or not os.path.exists(real_file):
        print("One of the files was not found!")
        input("\nPress Enter to continue...")
        return

    decoy_size = os.path.getsize(decoy_file)
    real_size = os.path.getsize(real_file)
    if decoy_size > STREAMING_THRESHOLD or real_size > STREAMING_THRESHOLD:
        print("Warning: One or both files are large. Hidden volume encryption may be resource-intensive.")

    print("\nDecoy Volume Authentication:")
    decoy_pwd, decoy_key_file_hash = choose_auth_method()
    decoy_argon_params = get_argon2_parameters_for_encryption()

    print("\nReal Volume Authentication:")
    real_pwd, real_key_file_hash = choose_auth_method()
    real_argon_params = get_argon2_parameters_for_encryption()

    # Generate ephemeral token for real volume
    token = generate_ephemeral_token(128)
    print(f"\nEphemeral token for real volume: {token}")
    token_bytes = token.encode()

    # Hash the token for storage
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    try:
        token_hash = ph.hash(token)
    except Exception as e:
        print("Error hashing token:", e)
        input("\nPress Enter to continue...")
        return

    try:
        decoy_data = read_file_data(decoy_file)
        real_data = read_file_data(real_file)
    except Exception as e:
        print(f"Error reading files: {e}")
        input("\nPress Enter to continue...")
        return

    # Encrypt decoy and real data
    enc_decoy_dict = encrypt_data_raw_chacha(decoy_data, decoy_pwd, decoy_argon_params)
    enc_real_dict = encrypt_data_raw_chacha(real_data, real_pwd, real_argon_params, extra=token_bytes)

    decoy_cipher = enc_decoy_dict['ciphertext']
    real_cipher = enc_real_dict['ciphertext']

    part1_length = len(decoy_cipher)
    part2_length = len(real_cipher)
    padding = secrets.token_bytes(random.randint(512, 2048))
    padding_length = len(padding)

    combined = decoy_cipher + padding + real_cipher
    combined_rs = rs_encode_data(combined)

    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    os.makedirs(folder, exist_ok=True)
    hidden_filename = generate_unique_filename("hidden_volume", ".enc")
    hidden_path = os.path.join(folder, hidden_filename)
    try:
        with open(hidden_path, 'wb') as fout:
            fout.write(combined_rs)
    except OSError as e:
        print(f"Error writing hidden volume file: {e}")
        # Limpeza parcial (nada a fazer se deu erro antes de criar .enc)
        input("\nPress Enter to continue...")
        return

    # Outer meta
    outer_meta = {
        'part1_length': part1_length,
        'padding_length': padding_length,
        'part2_length': part2_length,
        'decoy_nonce': enc_decoy_dict['nonce'],
        'decoy_salt': enc_decoy_dict['salt'],
        'decoy_argon2_time_cost': enc_decoy_dict['argon2_time_cost'],
        'decoy_argon2_memory_cost': enc_decoy_dict['argon2_memory_cost'],
        'decoy_argon2_parallelism': enc_decoy_dict['argon2_parallelism'],
        'created_at': datetime.datetime.now().isoformat()
    }
    if decoy_key_file_hash:
        outer_meta['decoy_key_file_hash'] = decoy_key_file_hash

    # Inner meta
    inner_meta = {
        'real_nonce': enc_real_dict['nonce'],
        'real_salt': enc_real_dict['salt'],
        'real_argon2_time_cost': enc_real_dict['argon2_time_cost'],
        'real_argon2_memory_cost': enc_real_dict['argon2_memory_cost'],
        'real_argon2_parallelism': enc_real_dict['argon2_parallelism'],
        'part2_token_hash': token_hash
    }
    if real_key_file_hash:
        inner_meta['real_key_file_hash'] = real_key_file_hash

    # Grava outer meta
    result_outer = encrypt_meta_json(hidden_path + ".meta", outer_meta, decoy_pwd)
    if result_outer is False:
        print("Failed to write outer metadata. Removing hidden volume file.")
        try:
            os.remove(hidden_path)
        except OSError:
            pass
        input("\nPress Enter to continue...")
        return

    # Grava inner meta
    result_inner = encrypt_meta_json(hidden_path + ".meta_hidden", inner_meta, real_pwd)
    if result_inner is False:
        print("Failed to write inner metadata. Removing hidden volume file.")
        try:
            os.remove(hidden_path)
            os.remove(hidden_path + ".meta")
        except OSError:
            pass
        input("\nPress Enter to continue...")
        return

    print("\nHidden volume created successfully!")
    print(f"File: {hidden_filename}")
    print("Save the ephemeral token securely for real volume access.")

    # LIMPAR senhas e token da memória
    for i in range(len(decoy_pwd)):
        decoy_pwd[i] = 0
    for i in range(len(real_pwd)):
        real_pwd[i] = 0
    token_bytes = b"\x00"
    token = "0"*len(token)

    input("\nPress Enter to continue...")


def decrypt_file(encrypted_file: str, outer_password: bytearray):
    """
    Detects if the volume is normal or hidden, and decrypts accordingly.
    """
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    file_path = os.path.join(folder, encrypted_file)
    meta_path = file_path + ".meta"

    meta_outer = decrypt_meta_json(meta_path, outer_password)
    if not meta_outer:
        print("Failed to decrypt metadata (incorrect password or corrupted)!")
        # Não limpamos password explicitamente aqui pois quem chamou pode fazê-lo,
        # mas para segurança, vamos limpar:
        for i in range(len(outer_password)):
            outer_password[i] = 0
        input("\nPress Enter to continue...")
        return

    meta_hidden_path = file_path + ".meta_hidden"
    is_hidden = os.path.exists(meta_hidden_path)

    if is_hidden:
        print("\nHidden volume detected.")
        if 'decoy_key_file_hash' in meta_outer:
            print("Key file is expected for decoy volume.")
            if not validate_key_file(meta_outer['decoy_key_file_hash']):
                # limpa password
                for i in range(len(outer_password)):
                    outer_password[i] = 0
                input("\nPress Enter to continue...")
                return

        try:
            with open(file_path, 'rb') as f:
                combined_rs = f.read()
        except Exception as e:
            print(f"Error reading hidden volume file: {e}")
            for i in range(len(outer_password)):
                outer_password[i] = 0
            input("\nPress Enter to continue...")
            return

        try:
            combined_data = rs_decode_data(combined_rs)
        except Exception:
            print("Error decoding RS data from hidden volume!")
            for i in range(len(outer_password)):
                outer_password[i] = 0
            input("\nPress Enter to continue...")
            return

        part1_length = meta_outer['part1_length']
        padding_length = meta_outer['padding_length']
        part2_length = meta_outer['part2_length']

        choice = input("Decrypt decoy volume (d) or real volume (r)? ").strip().lower()
        if choice not in ['d', 'r']:
            print("Invalid option!")
            for i in range(len(outer_password)):
                outer_password[i] = 0
            input("\nPress Enter to continue...")
            return

        if choice == 'd':
            target_cipher = combined_data[:part1_length]
            salt_str = meta_outer['decoy_salt']
            nonce_str = meta_outer['decoy_nonce']
            argon_params_choice = {
                'time_cost': meta_outer['decoy_argon2_time_cost'],
                'memory_cost': meta_outer['decoy_argon2_memory_cost'],
                'parallelism': meta_outer['decoy_argon2_parallelism']
            }
            print("\nUsing decoy volume authentication provided.")
            combined_pwd = outer_password
            extra_factor = None
        else:
            print("\nAuthenticate real volume (password + optional key file):")
            combined_pwd, _ = choose_auth_method()
            token = getpass.getpass("Enter ephemeral token for hidden volume access: ")
            from argon2 import PasswordHasher
            ph = PasswordHasher()
            meta_inner = decrypt_meta_json(meta_hidden_path, combined_pwd)
            if not meta_inner:
                print("Failed to decrypt real volume metadata!")
                # limpar senhas
                for i in range(len(outer_password)):
                    outer_password[i] = 0
                for i in range(len(combined_pwd)):
                    combined_pwd[i] = 0
                input("\nPress Enter to continue...")
                return
            try:
                ph.verify(meta_inner.get('part2_token_hash'), token)
            except Exception:
                print("Incorrect token!")
                for i in range(len(outer_password)):
                    outer_password[i] = 0
                for i in range(len(combined_pwd)):
                    combined_pwd[i] = 0
                token = "0"*len(token)
                input("\nPress Enter to continue...")
                return
            # se chegou até aqui, token é válido
            target_cipher = combined_data[part1_length + padding_length:
                                          part1_length + padding_length + part2_length]
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
        from cryptography.exceptions import InvalidTag
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
                print("Decryption failed (InvalidTag)!")
                if attempts >= MAX_ATTEMPTS:
                    print("Too many attempts! Please wait before trying again.")
                    time.sleep(30)
                    decrypted_data = None
                    break
                else:
                    time.sleep(2 ** attempts)
                    print("Incorrect authentication! Try again:")

        # Limpar senhas e token se houver
        for i in range(len(outer_password)):
            outer_password[i] = 0
        if choice == 'r':
            for i in range(len(combined_pwd)):
                combined_pwd[i] = 0
            token = "0"*len(token)

        if not decrypted_data:
            print("File decryption failed!")
            input("\nPress Enter to continue...")
            return

        out_name = f"decrypted_hidden_{'decoy' if choice == 'd' else 'real'}_" \
                   f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_" \
                   f"{secrets.token_hex(2)}.bin"
        out_path = os.path.join(folder, out_name)
        try:
            with open(out_path, 'wb') as f:
                f.write(decrypted_data)
            print(f"\nHidden volume ({'decoy' if choice=='d' else 'real'}) decrypted and saved as: {out_name}")
        except OSError as e:
            print(f"Error writing decrypted file: {e}")

    else:
        # Normal volume
        print("\nNormal volume detected.")
        # meta_plain = meta_outer (já descriptografado)
        meta_plain = meta_outer
        if not meta_plain:
            print("Failed to decrypt metadata (incorrect password or corrupted)!")
            for i in range(len(outer_password)):
                outer_password[i] = 0
            input("\nPress Enter to continue...")
            return
        if 'key_file_hash' in meta_plain:
            if not validate_key_file(meta_plain['key_file_hash']):
                for i in range(len(outer_password)):
                    outer_password[i] = 0
                input("\nPress Enter to continue...")
                return

        print("\nDecrypting normal volume with provided password...")
        if meta_plain.get('streaming', False):
            decrypt_data_streaming(file_path, outer_password)
        else:
            decrypt_data_single(file_path, outer_password)
        # limpeza do outer_password
        for i in range(len(outer_password)):
            outer_password[i] = 0

    input("\nPress Enter to continue...")


def change_real_volume_password():
    """
    Allows changing the password of the REAL (hidden) volume part without exposing the decoy.
    """
    clear_screen()
    print("=== CHANGE REAL VOLUME PASSWORD (HIDDEN) ===")
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    files = [f for f in os.listdir(folder) if f.endswith('.enc')]

    if not files:
        print("No encrypted files found!")
        input("\nPress Enter to go back...")
        return

    print("\nAvailable files:")
    for i, f in enumerate(files, 1):
        print(f"[{i}] {f}")

    try:
        choice = int(input("\nSelect file (hidden volume): ")) - 1
        selected_file = files[choice]
    except Exception:
        print("Invalid selection!")
        input("\nPress Enter to continue...")
        return

    file_path = os.path.join(folder, selected_file)
    meta_outer_path = file_path + ".meta"
    meta_inner_path = file_path + ".meta_hidden"

    print("\nAuthenticate decoy volume to decrypt outer metadata:")
    decoy_pwd, _ = choose_auth_method()

    meta_outer = decrypt_meta_json(meta_outer_path, decoy_pwd)
    if not meta_outer:
        print("Failed to decrypt outer metadata with decoy volume authentication!")
        for i in range(len(decoy_pwd)):
            decoy_pwd[i] = 0
        input("\nPress Enter to continue...")
        return
    if not os.path.exists(meta_inner_path):
        print("This file is not a hidden volume!")
        for i in range(len(decoy_pwd)):
            decoy_pwd[i] = 0
        input("\nPress Enter to continue...")
        return

    try:
        with open(file_path, 'rb') as f:
            combined_rs = f.read()
    except Exception as e:
        print(f"Error reading RS data from hidden volume: {e}")
        for i in range(len(decoy_pwd)):
            decoy_pwd[i] = 0
        input("\nPress Enter to continue...")
        return

    try:
        combined_data = rs_decode_data(combined_rs)
    except Exception:
        print("Error decoding RS data from hidden volume!")
        for i in range(len(decoy_pwd)):
            decoy_pwd[i] = 0
        input("\nPress Enter to continue...")
        return

    part1_length = meta_outer['part1_length']
    padding_length = meta_outer['padding_length']
    part2_length = meta_outer['part2_length']

    print("\nEnter ephemeral token for real volume access:")
    token = getpass.getpass("> ")
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    print("\nAuthenticate real volume to decrypt the real part (password + optional key file):")
    real_pwd, _ = choose_auth_method()

    meta_inner = decrypt_meta_json(meta_inner_path, real_pwd)
    if not meta_inner:
        print("Failed to decrypt real volume metadata!")
        for i in range(len(decoy_pwd)):
            decoy_pwd[i] = 0
        for i in range(len(real_pwd)):
            real_pwd[i] = 0
        token = "0"*len(token)
        input("\nPress Enter to continue...")
        return

    try:
        ph.verify(meta_inner.get('part2_token_hash'), token)
    except Exception:
        print("Incorrect token!")
        for i in range(len(decoy_pwd)):
            decoy_pwd[i] = 0
        for i in range(len(real_pwd)):
            real_pwd[i] = 0
        token = "0"*len(token)
        input("\nPress Enter to continue...")
        return

    start_real = part1_length + padding_length
    end_real = start_real + part2_length
    real_cipher = combined_data[start_real:end_real]

    real_argon_params = {
        'time_cost': meta_inner['real_argon2_time_cost'],
        'memory_cost': meta_inner['real_argon2_memory_cost'],
        'parallelism': meta_inner['real_argon2_parallelism']
    }
    real_salt_b64 = meta_inner['real_salt']
    real_nonce_b64 = meta_inner['real_nonce']

    from cryptography.exceptions import InvalidTag

    attempts = 0
    real_plain_data = None
    while attempts < MAX_ATTEMPTS:
        enc_dict = {
            'ciphertext': real_cipher,
            'nonce': real_nonce_b64,
            'salt': real_salt_b64,
            'argon2_time_cost': real_argon_params["time_cost"],
            'argon2_memory_cost': real_argon_params["memory_cost"],
            'argon2_parallelism': real_argon_params["parallelism"]
        }
        try:
            real_plain_data = decrypt_data_raw_chacha(enc_dict, real_pwd, extra=token.encode())
            break
        except InvalidTag:
            attempts += 1
            print("Decryption failed for real part (incorrect authentication)!")
            if attempts >= MAX_ATTEMPTS:
                print("Too many attempts! Aborting.")
                real_plain_data = None
                break
            else:
                time.sleep(2 ** attempts)
                print("Try again:")
    if real_plain_data is None:
        # Limpa
        for i in range(len(decoy_pwd)):
            decoy_pwd[i] = 0
        for i in range(len(real_pwd)):
            real_pwd[i] = 0
        token = "0"*len(token)
        input("\nPress Enter to continue...")
        return

    print("\nReal part decrypted successfully. Now set new authentication for the real volume:")
    new_real_pwd, key_file_hash_new = choose_auth_method()
    new_real_argon_params = get_argon2_parameters_for_encryption()

    enc_real_dict_new = encrypt_data_raw_chacha(real_plain_data, new_real_pwd,
                                                new_real_argon_params,
                                                extra=token.encode())
    new_real_cipher = enc_real_dict_new['ciphertext']

    combined_new = combined_data[:part1_length + padding_length] + new_real_cipher

    # Re-encode with RS
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file_name = temp_file.name
    temp_file.close()

    try:
        with open(temp_file_name, 'wb') as f:
            f.write(rs_encode_data(combined_new))
        with open(temp_file_name, 'rb') as f:
            new_rs_data = f.read()
        with open(file_path, 'wb') as f:
            f.write(new_rs_data)
    except Exception as e:
        print(f"Error writing updated hidden volume: {e}")
        # remover temp
        try:
            os.remove(temp_file_name)
        except OSError:
            pass
        # limpeza
        for i in range(len(decoy_pwd)):
            decoy_pwd[i] = 0
        for i in range(len(real_pwd)):
            real_pwd[i] = 0
        token = "0"*len(token)
        for i in range(len(new_real_pwd)):
            new_real_pwd[i] = 0
        input("\nPress Enter to continue...")
        return

    # remover arquivo temporário com sucesso
    try:
        os.remove(temp_file_name)
    except OSError as e:
        print(f"Warning: temporary file not removed: {e}")

    meta_inner['real_salt'] = enc_real_dict_new['salt']
    meta_inner['real_nonce'] = enc_real_dict_new['nonce']
    meta_inner['real_argon2_time_cost'] = enc_real_dict_new['argon2_time_cost']
    meta_inner['real_argon2_memory_cost'] = enc_real_dict_new['argon2_memory_cost']
    meta_inner['real_argon2_parallelism'] = enc_real_dict_new['argon2_parallelism']

    if key_file_hash_new:
        meta_inner['real_key_file_hash'] = key_file_hash_new
    else:
        meta_inner.pop('real_key_file_hash', None)

    # Grava meta_inner com nova senha
    result_change = encrypt_meta_json(meta_inner_path, meta_inner, new_real_pwd)
    if result_change is False:
        print("Could not rewrite inner metadata with new real password.")
        # não reverte a mudança no .enc, mas avisa
        # pois passamos os dados atualizados
        pass

    print("\nReal volume password updated successfully!")

    # LIMPAR senhas e token
    for i in range(len(decoy_pwd)):
        decoy_pwd[i] = 0
    for i in range(len(real_pwd)):
        real_pwd[i] = 0
    for i in range(len(new_real_pwd)):
        new_real_pwd[i] = 0
    token = "0"*len(token)

    input("\nPress Enter to continue...")


def encrypt_data_raw_chacha(data: bytes, password: bytearray,
                            argon_params: dict, extra: bytes = None) -> dict:
    """
    Encrypts data using ChaCha20Poly1305. Argon2 is used to derive the key.
    """
    import secrets
    salt = secrets.token_bytes(32)
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

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


def decrypt_data_raw_chacha(enc_dict: dict, password: bytearray,
                            extra: bytes = None) -> bytes:
    """
    Decrypts data that was encrypted by encrypt_data_raw_chacha.
    """
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
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
