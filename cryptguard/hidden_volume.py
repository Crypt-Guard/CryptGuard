# hidden_volume.py

import os
import base64
import datetime
import time
import random
import secrets
from argon2 import PasswordHasher
import getpass

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
    Creates a hidden volume with enhanced deniability:
      - Encrypts two files (decoy volume and real volume) without RS,
      - Concatenates with padding,
      - Applies RS on the combined data and saves separate metadata:
          * Outer Meta (for decoy volume) encrypted with the decoy volume password, without indicating hidden.
          * Inner Meta (for real volume) encrypted with the real volume password, containing details of the hidden volume.
    
    The real volume is encrypted using authentication (password + optional key file)
    and an ephemeral token, which is incorporated into key derivation.
    """
    clear_screen()
    print("=== ENCRYPT HIDDEN VOLUME ===")
    decoy_file = os.path.normpath(input("Enter path for decoy file: ").strip())
    real_file = os.path.normpath(input("Enter path for real file: ").strip())

    if not os.path.exists(decoy_file) or not os.path.exists(real_file):
        print("One of the files was not found!")
        input("\nPress Enter to continue...")
        return

    # Warn if files are large (streaming for hidden volume not implemented)
    decoy_size = os.path.getsize(decoy_file)
    real_size = os.path.getsize(real_file)
    if decoy_size > STREAMING_THRESHOLD or real_size > STREAMING_THRESHOLD:
        print("Warning: One or both files are large. Hidden volume encryption may consume significant memory as streaming is not implemented.")
    
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

    try:
        decoy_data = read_file_data(decoy_file)
        real_data = read_file_data(real_file)
    except Exception as e:
        print(f"Error reading files: {e}")
        input("\nPress Enter to continue...")
        return

    enc_decoy_dict = encrypt_data_raw_chacha(decoy_data, decoy_pwd, decoy_argon_params)
    enc_real_dict  = encrypt_data_raw_chacha(real_data, real_pwd, real_argon_params, extra=token_bytes)

    decoy_cipher = enc_decoy_dict['ciphertext']
    real_cipher  = enc_real_dict['ciphertext']

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
    with open(hidden_path, 'wb') as fout:
        fout.write(combined_rs)

    # Compute token hash for verification
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    # Create Outer Meta (for decoy volume) using generic field names
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

    # Create Inner Meta (for real volume)
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

    # Save metadata in two files:
    # Outer Meta: <hidden_path>.meta (accessible with decoy password)
    # Inner Meta: <hidden_path>.meta_hidden (accessible with real password)
    encrypt_meta_json(hidden_path + ".meta", outer_meta, decoy_pwd)
    encrypt_meta_json(hidden_path + ".meta_hidden", inner_meta, real_pwd)

    print("\nHidden volume created successfully!")
    print(f"File: {hidden_filename}")
    print("Save the ephemeral token securely for real volume access.")
    input("\nPress Enter to continue...")

def decrypt_file(encrypted_file: str, outer_password: bytearray):
    """
    Detects whether the volume is normal or hidden and calls the appropriate routine.
    For hidden volumes, uses:
      - The .meta file (decoy volume) decryptable with outer_password.
      - The .meta_hidden file (real volume) decryptable with the real volume password.
    For real volume, the ephemeral token is incorporated into key derivation.
    For normal volumes, unified authentication is used.
    """
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    file_path = os.path.join(folder, encrypted_file)
    meta_path = file_path + ".meta"

    meta_outer = decrypt_meta_json(meta_path, outer_password)
    if not meta_outer:
        print("Failed to decrypt metadata (incorrect password or corrupted)!")
        input("\nPress Enter to continue...")
        return

    # Determine hidden volume by checking if .meta_hidden exists
    meta_hidden_path = file_path + ".meta_hidden"
    is_hidden = os.path.exists(meta_hidden_path)

    if is_hidden:
        print("\nHidden volume detected.")
        if 'decoy_key_file_hash' in meta_outer:
            print("Key file detected for decoy volume.")
            if not validate_key_file(meta_outer['decoy_key_file_hash']):
                input("\nPress Enter to continue...")
                return

        with open(file_path, 'rb') as f:
            combined_rs = f.read()
        try:
            combined_data = rs_decode_data(combined_rs)
        except Exception:
            print("Error decoding RS data from hidden volume!")
            input("\nPress Enter to continue...")
            return

        part1_length   = meta_outer['part1_length']
        padding_length = meta_outer['padding_length']
        part2_length   = meta_outer['part2_length']

        choice = input("Decrypt decoy volume (d) or real volume (r)? ").strip().lower()
        if choice not in ['d', 'r']:
            print("Invalid option!")
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
            ph = PasswordHasher()
            token_hash = ph.hash(token)
            meta_inner = decrypt_meta_json(meta_hidden_path, combined_pwd)
            if not meta_inner:
                print("Failed to decrypt real volume metadata (incorrect password or corrupted)!")
                input("\nPress Enter to continue...")
                return
            try:
                ph.verify(meta_inner.get('part2_token_hash'), token)
            except:
                print("Incorrect token!")
                input("\nPress Enter to continue...")
                return
                print("Incorrect token!")
                input("\nPress Enter to continue...")
                return
            target_cipher = combined_data[part1_length + padding_length : part1_length + padding_length + part2_length]
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
                print("Decryption failed (InvalidTag)!")
                if attempts >= MAX_ATTEMPTS:
                    print("Too many attempts! Please wait before trying again.")
                    time.sleep(30)
                    input("\nPress Enter to continue...")
                    return
                else:
                    time.sleep(2 ** attempts)
                    print("Incorrect authentication! Try again:")
        else:
            return

        out_name = f"decrypted_hidden_{'decoy' if choice=='d' else 'real'}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
        out_path = os.path.join(folder, out_name)
        with open(out_path, 'wb') as f:
            f.write(decrypted_data)
        print(f"\nHidden volume ({'decoy' if choice=='d' else 'real'}) decrypted and saved as: {out_name}")

    else:
        # Normal volume
        print("\nNormal volume detected.")
        meta_plain = decrypt_meta_json(meta_path, outer_password)
        if not meta_plain:
            print("Failed to decrypt metadata (incorrect password or corrupted)!")
            input("\nPress Enter to continue...")
            return
        if 'key_file_hash' in meta_plain:
            if not validate_key_file(meta_plain['key_file_hash']):
                input("\nPress Enter to continue...")
                return
        print("\nDecrypting normal volume with provided password...")
        if meta_plain.get('streaming', False):
            decrypt_data_streaming(file_path, outer_password)
        else:
            decrypt_data_single(file_path, outer_password)

    input("\nPress Enter to continue...")

def change_real_volume_password():
    """
    Allows changing the password of the REAL VOLUME (hidden part) without exposing the decoy volume.
    Flow:
      1) Select the .enc file (hidden volume).
      2) Authenticate with the decoy volume to decrypt outer metadata.
      3) Authenticate real volume (password + optional key file) along with the ephemeral token.
      4) Decrypt the real part.
      5) Ask for new authentication for the real volume.
      6) Re-encrypt the real part with new authentication and update inner metadata.
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
        input("\nPress Enter to continue...")
        return
    if not os.path.exists(meta_inner_path):
        print("This file is not a hidden volume!")
        input("\nPress Enter to continue...")
        return

    with open(file_path, 'rb') as f:
        combined_rs = f.read()

    try:
        combined_data = rs_decode_data(combined_rs)
    except Exception:
        print("Error decoding RS data from hidden volume!")
        input("\nPress Enter to continue...")
        return

    part1_length   = meta_outer['part1_length']
    padding_length = meta_outer['padding_length']
    part2_length   = meta_outer['part2_length']

    print("\nEnter ephemeral token for real volume access:")
    token = getpass.getpass("> ")
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    print("\nAuthenticate real volume to decrypt the real part (password + optional key file):")
    real_pwd, _ = choose_auth_method()

    meta_inner = decrypt_meta_json(meta_inner_path, real_pwd)
    if not meta_inner:
        print("Failed to decrypt real volume metadata!")
        input("\nPress Enter to continue...")
        return

    # Validate real volume key file if applicable (after decrypting meta_inner)
    if 'real_key_file_hash' in meta_inner:
        print("Key file detected for real volume.")
        if not validate_key_file(meta_inner['real_key_file_hash']):
            input("\nPress Enter to continue...")
            return

    if token_hash != meta_inner.get('part2_token_hash'):
        print("Incorrect token!")
        input("\nPress Enter to continue...")
        return

    start_real = part1_length + padding_length
    end_real = start_real + part2_length
    real_cipher  = combined_data[start_real:end_real]

    real_argon_params = {
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
                input("\nPress Enter to continue...")
                return
            else:
                time.sleep(2 ** attempts)
                print("Try again:")
    if real_plain_data is None:
        return

    print("\nReal part decrypted successfully. Now set new authentication for the real volume:")
    new_real_pwd, key_file_hash_new = choose_auth_method()
    new_real_argon_params = get_argon2_parameters_for_encryption()

    enc_real_dict_new = encrypt_data_raw_chacha(real_plain_data, new_real_pwd, new_real_argon_params, extra=token.encode())
    new_real_cipher = enc_real_dict_new['ciphertext']

    # Update combined data, preserving decoy and padding unchanged
    combined_new = combined_data[:part1_length + padding_length] + new_real_cipher
    try:
        import tempfile
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file_name = temp_file.name
        temp_file.close()
        with open(temp_file_name, 'wb') as f:
            f.write(rs_encode_data(combined_new))
        with open(temp_file_name, 'rb') as f:
            new_rs_data = f.read()
        with open(file_path, 'wb') as f:
            f.write(new_rs_data)
    except Exception as e:
        print(f"Error writing updated hidden volume: {e}")
        input("\nPress Enter to continue...")
        return

    meta_inner['real_salt'] = enc_real_dict_new['salt']
    meta_inner['real_nonce'] = enc_real_dict_new['nonce']
    meta_inner['real_argon2_time_cost'] = enc_real_dict_new['argon2_time_cost']
    meta_inner['real_argon2_memory_cost'] = enc_real_dict_new['argon2_memory_cost']
    meta_inner['real_argon2_parallelism'] = enc_real_dict_new['argon2_parallelism']

    if key_file_hash_new:
        meta_inner['real_key_file_hash'] = key_file_hash_new
    else:
        meta_inner.pop('real_key_file_hash', None)

    encrypt_meta_json(meta_inner_path, meta_inner, new_real_pwd)

    print("\nReal volume password updated successfully!")
    input("\nPress Enter to continue...")

# The following helper functions are used by hidden_volume:

def encrypt_data_raw_chacha(data: bytes, password: bytearray, argon_params: dict, extra: bytes = None):
    """
    Encrypts data using ChaCha20Poly1305.
    Optionally concatenates 'extra' to the password for key derivation.
    """
    import secrets
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
    Decrypts data encrypted by encrypt_data_raw_chacha.
    Uses the optional 'extra' in key derivation if provided.
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
