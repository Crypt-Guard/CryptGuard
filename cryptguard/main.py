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

def list_encrypted_files():
    """
    Returns a list of .enc files in ~/Documents/Encoded_files_folder.
    """
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    if not os.path.exists(folder):
        return []
    files = [f for f in os.listdir(folder) if f.endswith('.enc')]
    result = []
    for f in files:
        result.append((f, "??"))
    return result

def select_file_from_list(prompt_message, files):
    """
    Helper function to display a list of files and select one.
    """
    print(prompt_message)
    for i, f in enumerate(files, 1):
        print(f"[{i}] {f}")
    try:
        choice = int(input("\nSelect a file: ")) - 1
        return files[choice]
    except Exception:
        print("Invalid selection!")
        return None

def ask_chunk_size():
    """
    Allows the user to set the chunk size for streaming.
    Returns an integer; if invalid or empty, returns the default CHUNK_SIZE.
    """
    default_cs = CHUNK_SIZE
    print(f"Default chunk size is {default_cs} bytes.")
    user_input = input("Enter new chunk size (or press ENTER to keep default): ").strip()
    if not user_input:
        return default_cs
    try:
        new_size = int(user_input)
        if new_size < 1024:
            print("Value too small, forcing 1024.")
            return 1024
        return new_size
    except ValueError:
        print("Invalid input, using default chunk size.")
        return default_cs

def encrypt_text():
    """
    Asks the user for a message and encrypts it in single-shot mode.
    """
    clear_screen()
    print("=== ENCRYPT TEXT ===")
    message = input("Enter your message: ").encode('utf-8')
    combined_pwd, key_file_hash = choose_auth_method()
    encrypt_data_single(message, combined_pwd, "text", ".txt", key_file_hash)
    input("\nPress Enter to continue...")

def encrypt_file(file_type: str):
    """
    Encrypts a single file (image, PDF, audio, etc.) using unified authentication.
    If the file is large, uses streaming mode.
    """
    clear_screen()
    print(f"=== ENCRYPT {file_type.upper()} ===")
    file_path = os.path.normpath(input("Enter file path: ").strip())
    if not os.path.exists(file_path):
        print("File not found!")
        input("\nPress Enter to continue...")
        return
    combined_pwd, key_file_hash = choose_auth_method()
    ext = os.path.splitext(file_path)[1]
    file_size = os.path.getsize(file_path)
    if file_size > STREAMING_THRESHOLD:
        print("\nLarge file detected => using streaming mode.\n")
        chunk_size = ask_chunk_size()
        encrypt_data_streaming(file_path, combined_pwd, file_type.lower(), ext,
                               key_file_hash, chunk_size=chunk_size)
    else:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        encrypt_data_single(file_data, combined_pwd, file_type.lower(), ext, key_file_hash)
    input("\nPress Enter to continue...")

def encrypt_multiple_files():
    """
    Zips multiple files and then encrypts the zip archive.
    """
    clear_screen()
    print("=== ENCRYPT MULTIPLE FILES ===")
    files = []
    while True:
        entry = input("Enter file path (leave blank to finish): ").strip()
        if entry == "":
            break
        file_path = os.path.normpath(entry)
        if not os.path.exists(file_path):
            print("File not found! Try again.")
        else:
            files.append(file_path)
    if not files:
        print("No files selected!")
        input("\nPress Enter to continue...")
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
            print("\nLarge file detected => using streaming mode.\n")
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
    input("\nPress Enter to continue...")

def decrypt_menu():
    """
    Lists encrypted files and allows the user to select one for decryption.
    For hidden volumes, additional authentication is requested.
    """
    clear_screen()
    print("=== DECRYPT FILE ===")
    files = list_encrypted_files()
    if not files:
        print("No encrypted files found!")
        input("\nPress Enter to go back...")
        return
    print("\nAvailable files:")
    for i, (f, vol_type) in enumerate(files, 1):
        print(f"[{i}] {f} ({vol_type})")
    try:
        choice = int(input("\nSelect a file: ")) - 1
        selected_file, _ = files[choice]
    except Exception:
        print("Invalid selection!")
        input("\nPress Enter to continue...")
        return
    print("\nSelect authentication method for decryption:")
    combined_pwd, _ = choose_auth_method()
    decrypt_file(selected_file, combined_pwd)

def reencrypt_file():
    """
    Performs key rolling (re-encryption):
      - Decrypts the file using old authentication,
      - Asks for new authentication and re-encrypts,
      - Optionally removes the old encrypted file.
    """
    clear_screen()
    print("=== RE-ENCRYPT (KEY ROLLING) ===")
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
        choice = int(input("\nSelect a file to re-encrypt: ")) - 1
        selected_file = files[choice]
    except Exception:
        print("Invalid selection!")
        input("\nPress Enter to continue...")
        return
    print(f"\nUsing old authentication to decrypt {selected_file}.")
    old_pwd, _ = choose_auth_method()
    enc_path = os.path.join(folder, selected_file)
    from metadata import decrypt_meta_json
    meta_plain = decrypt_meta_json(enc_path + ".meta", old_pwd)
    if not meta_plain:
        print("Failed to decrypt metadata (incorrect authentication or corrupted data)!")
        input("\nPress Enter to continue...")
        return
    # Check for hidden volume by presence of .meta_hidden
    if os.path.exists(enc_path + ".meta_hidden"):
        print("Re-encrypt is not supported for hidden volumes in this version.")
        input("\nPress Enter to continue...")
        return
    streaming = meta_plain.get("streaming", False)
    print("\nDecrypting with old authentication ...")
    if streaming:
        decrypt_data_streaming(enc_path, old_pwd)
    else:
        decrypt_data_single(enc_path, old_pwd)
    folder_files = os.listdir(folder)
    newly_created = [f for f in folder_files if f.startswith("decrypted_")]
    if not newly_created:
        print("Could not find the decrypted file!")
        input("\nPress Enter to continue...")
        return
    newly_created_paths = [os.path.join(folder, nf) for nf in newly_created]
    newest = max(newly_created_paths, key=os.path.getmtime)
    print(f"Decrypted file detected: {os.path.basename(newest)}")
    print("\nEnter new authentication (password + optional key file) for re-encryption:")
    new_pwd, key_file_hash_new = choose_auth_method()
    print("\nSelect re-encryption mode:")
    print("[1] Single-Shot")
    print("[2] Streaming")
    mode_choice = input("Option: ").strip()
    mode_streaming = (mode_choice == '2')
    _, ext = os.path.splitext(newest)
    if mode_streaming:
        chunk_size = ask_chunk_size()
        encrypt_data_streaming(newest, new_pwd, "reenc", ext, key_file_hash_new, chunk_size=chunk_size)
    else:
        with open(newest, 'rb') as f:
            data_in = f.read()
        encrypt_data_single(data_in, new_pwd, "reenc", ext, key_file_hash_new)
    remove_old = input("\nRemove old .enc file? (y/n): ").strip().lower()
    if remove_old == 'y':
        try:
            os.remove(enc_path)
            os.remove(enc_path + ".meta")
            print("Old file removed.")
        except:
            print("Could not remove old file.")
    remove_decrypted = input("Remove decrypted file? (y/n): ").strip().lower()
    if remove_decrypted == 'y':
        try:
            os.remove(newest)
            print("Decrypted file removed.")
        except:
            print("Could not remove decrypted file.")
    input("\nKey rolling completed. Press Enter to continue...")

def generate_ephemeral_token_menu():
    """
    Generates an ephemeral token in hex and displays it.
    """
    clear_screen()
    print("=== GENERATE EPHEMERAL TOKEN ===")
    token = generate_ephemeral_token(128)
    print(f"Generated token (use for hidden volumes, etc.): {token}")
    input("\nPress Enter to continue...")

def main_menu():
    """
    Main menu of CryptGuard with improved usability and unified authentication flows.
    """
    while True:
        clear_screen()
        print("\n=== CRYPTGUARD - ADVANCED ENCRYPTION SYSTEM ===")
        print("""
[1] Encrypt Text
[2] Encrypt File (Image/PDF/Audio)
[3] Decrypt File
[4] Encrypt Multiple Files
[5] Generate Ephemeral Token
[6] Create Hidden Volume (Plausible Deniability)
[7] Re-Encrypt (Key Rolling) - (for normal volumes)
[8] Change Real Volume Password (Hidden)
[0] Exit
        """)
        choice = input("Select an option: ").strip()
        if choice == '1':
            encrypt_text()
        elif choice == '2':
            clear_screen()
            print("File Type:")
            print("[1] Image")
            print("[2] PDF")
            print("[3] Audio")
            file_choice = input("Select: ").strip()
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
            print("Exiting...")
            time.sleep(1)
            break
        else:
            print("Invalid option!")
            time.sleep(1)

if __name__ == "__main__":
    main_menu()
