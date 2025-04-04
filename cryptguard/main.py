import os
import time
import tempfile
import zipfile

import config
from password_utils import choose_auth_method
from single_shot import encrypt_data_single, decrypt_data_single
from streaming import encrypt_data_streaming, decrypt_data_streaming
from hidden_volume import encrypt_hidden_volume, decrypt_file, change_real_volume_password
from utils import clear_screen, generate_ephemeral_token, generate_unique_filename
from metadata import decrypt_meta_json
from file_chooser import select_file_for_encryption, select_files_for_decryption


def list_encrypted_files():
    """
    Returns a list of tuples (filename, volume_type) for .enc files
    in the ~/Documents/Encoded_files_folder.
    Detecta se é hidden ou normal com base em .meta_hidden.
    """
    folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
    if not os.path.exists(folder):
        return []
    files = [f for f in os.listdir(folder) if f.endswith('.enc')]
    result = []
    for f in files:
        meta_hidden = os.path.join(folder, f + ".meta_hidden")
        if os.path.exists(meta_hidden):
            vol_type = "hidden"
        else:
            vol_type = "normal"
        result.append((f, vol_type))
    return result


def ask_chunk_size():
    """
    Lets the user set the chunk size for streaming.
    """
    default_cs = config.CHUNK_SIZE
    print(f"Default chunk size is {default_cs} bytes.")
    user_input = input("Enter new chunk size (or press ENTER to keep default): ").strip()
    if not user_input:
        return default_cs
    try:
        new_size = int(user_input)
        if new_size < 1024:
            print("Value too small, forcing 1024.")
            return 1024
        if new_size > config.MAX_CHUNK_SIZE:
            print(f"Value too large, forcing {config.MAX_CHUNK_SIZE} bytes.")
            return config.MAX_CHUNK_SIZE
        return new_size
    except ValueError:
        print("Invalid input, using default chunk size.")
        return default_cs


def encrypt_text():
    """
    Asks the user for text input and encrypts in single-shot mode.
    """
    clear_screen()
    print("=== ENCRYPT TEXT ===")
    message = input("Enter your message: ").encode('utf-8')
    combined_pwd, key_file_hash = choose_auth_method()
    try:
        encrypt_data_single(message, combined_pwd, "text", ".txt", key_file_hash)
        print("Encryption completed successfully.")
    except Exception as e:
        print(f"Encryption failed: {e}")
    finally:
        for i in range(len(combined_pwd)):
            combined_pwd[i] = 0
    input("\nPress Enter to continue...")


def encrypt_multiple_files():
    """
    Zips multiple files selected by the user, then encrypts the resulting zip.
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

        # Gera um zip com todos os arquivos selecionados
        with zipfile.ZipFile(temp_zip_name, 'w') as zipf:
            for f in files:
                zipf.write(f, arcname=os.path.basename(f))

        combined_pwd, key_file_hash = choose_auth_method()

        try:
            zip_size = os.path.getsize(temp_zip_name)
        except OSError as e:
            print(f"Error getting size of temp zip: {e}")
            input("\nPress Enter to continue...")
            return

        # Se for maior que STREAMING_THRESHOLD, usar streaming
        if zip_size > config.STREAMING_THRESHOLD:
            print("\nLarge file detected => using streaming mode.\n")
            chunk_size = ask_chunk_size()
            try:
                encrypt_data_streaming(temp_zip_name, combined_pwd, "multi", ".zip", key_file_hash,
                                       chunk_size=chunk_size)
                print("Encryption completed successfully.")
            except Exception as e:
                print(f"Encryption failed: {e}")
        else:
            # Modo single-shot
            try:
                with open(temp_zip_name, 'rb') as f:
                    zip_data = f.read()
                encrypt_data_single(zip_data, combined_pwd, "multi", ".zip", key_file_hash)
                print("Encryption completed successfully.")
            except Exception as e:
                print(f"Encryption failed: {e}")

    finally:
        if temp_zip is not None and os.path.exists(temp_zip_name):
            try:
                os.remove(temp_zip_name)
            except Exception:
                pass
        # limpar combined_pwd
        if 'combined_pwd' in locals():
            for i in range(len(combined_pwd)):
                combined_pwd[i] = 0

    input("\nPress Enter to continue...")


def decrypt_menu():
    """
    Lists encrypted files in the default folder and decrypts one.
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
    try:
        decrypt_file(selected_file, combined_pwd)
    except Exception as e:
        print(f"Decryption failed: {e}")
    finally:
        for i in range(len(combined_pwd)):
            combined_pwd[i] = 0

    input("\nPress Enter to continue...")


def reencrypt_file():
    """
    Key rolling for normal volumes:
      - Decrypt with old authentication
      - Re-encrypt with new authentication
      - Optionally remove old files
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
    meta_plain = decrypt_meta_json(enc_path + ".meta", old_pwd)
    if not meta_plain:
        print("Failed to decrypt metadata (incorrect authentication or corrupted data)!")
        for i in range(len(old_pwd)):
            old_pwd[i] = 0
        input("\nPress Enter to continue...")
        return

    # Verifica se é hidden volume
    if os.path.exists(enc_path + ".meta_hidden"):
        print("Re-encrypt is not supported for hidden volumes in this version.")
        for i in range(len(old_pwd)):
            old_pwd[i] = 0
        input("\nPress Enter to continue...")
        return

    streaming = meta_plain.get("streaming", False)
    print("\nDecrypting with old authentication ...")
    out_name = None
    try:
        if streaming:
            decrypt_data_streaming(enc_path, old_pwd)
        else:
            decrypt_data_single(enc_path, old_pwd)

        # localiza o arquivo gerado
        folder_files = os.listdir(folder)
        newly_created = [f for f in folder_files if f.startswith("decrypted_")]
        if not newly_created:
            print("Could not find the decrypted file!")
            return

        newly_created_paths = [os.path.join(folder, nf) for nf in newly_created]
        newest = max(newly_created_paths, key=os.path.getmtime)
        print(f"Decrypted file detected: {os.path.basename(newest)}")
        out_name = newest
    except Exception as e:
        print(f"Decryption failed: {e}")
    finally:
        for i in range(len(old_pwd)):
            old_pwd[i] = 0

    if not out_name:
        input("\nPress Enter to continue...")
        return

    print("\nEnter new authentication (password + optional key file) for re-encryption:")
    new_pwd, key_file_hash_new = choose_auth_method()

    print("\nSelect re-encryption mode:")
    print("[1] Single-Shot")
    print("[2] Streaming")
    mode_choice = input("Option: ").strip()
    mode_streaming = (mode_choice == '2')
    _, ext = os.path.splitext(out_name)

    try:
        if mode_streaming:
            chunk_size = ask_chunk_size()
            encrypt_data_streaming(out_name, new_pwd, "reenc", ext, key_file_hash_new, chunk_size=chunk_size)
        else:
            with open(out_name, 'rb') as f:
                data_in = f.read()
            encrypt_data_single(data_in, new_pwd, "reenc", ext, key_file_hash_new)
        print("Re-encryption completed successfully.")
    except Exception as e:
        print(f"Re-encryption failed: {e}")

    remove_old = input("\nRemove old .enc file? (y/n): ").strip().lower()
    if remove_old == 'y':
        try:
            os.remove(enc_path)
            os.remove(enc_path + ".meta")
            print("Old file removed.")
        except Exception:
            print("Could not remove old file.")

    remove_decrypted = input("Remove decrypted file? (y/n): ").strip().lower()
    if remove_decrypted == 'y':
        try:
            os.remove(out_name)
            print("Decrypted file removed.")
        except Exception:
            print("Could not remove decrypted file.")

    for i in range(len(new_pwd)):
        new_pwd[i] = 0

    input("\nKey rolling completed. Press Enter to continue...")


def generate_ephemeral_token_menu():
    """
    Generates and displays a random ephemeral token in hex.
    Now optionally does not save to disk for better security.
    """
    clear_screen()
    print("=== GENERATE EPHEMERAL TOKEN ===")
    token = generate_ephemeral_token(128)

    save_choice = input("Save token to file? (y/N): ").strip().lower()
    if save_choice == 'y':
        out_file = "ephemeral_token.txt"
        try:
            with open(out_file, "w") as f:
                f.write(token + "\n")
            print(f"Generated token and saved to: {out_file}")
            print("Remember to delete or protect this file securely!")
        except OSError as e:
            print(f"Error writing ephemeral token to file: {e}")
            print(f"Here is the token anyway (use with caution): {token}")
    else:
        print(f"Ephemeral token (not saved): {token}")

    input("\nPress Enter to continue...")


def menu_file_dialog():
    """
    Submenu for selecting whether to encrypt or decrypt via a file chooser dialog.
    """
    clear_screen()
    print("=== OPEN FILE SELECTION WINDOW ===")
    print("""
[1] Encrypt a File
[2] Decrypt a File
[0] Back
    """)
    subchoice = input("Select an option: ").strip()

    if subchoice == '1':
        encrypt_with_dialog()
    elif subchoice == '2':
        decrypt_with_dialog()
    else:
        return


def encrypt_with_dialog():
    clear_screen()
    print("=== ENCRYPTING VIA FILE DIALOG ===")
    file_path = select_file_for_encryption()
    if not file_path:
        print("No file selected (or dialog canceled)!")
        input("Press Enter to continue...")
        return

    combined_pwd, key_file_hash = choose_auth_method()
    try:
        ext = os.path.splitext(file_path)[1]
        file_size = os.path.getsize(file_path)
        if file_size > config.STREAMING_THRESHOLD:
            print("\nLarge file detected => using streaming mode.\n")
            chunk_size = ask_chunk_size()
            encrypt_data_streaming(file_path, combined_pwd, "file", ext, key_file_hash, chunk_size=chunk_size)
        else:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            encrypt_data_single(file_data, combined_pwd, "file", ext, key_file_hash)
        print("Encryption completed successfully.")
    except Exception as e:
        print(f"Encryption failed: {e}")
    finally:
        for i in range(len(combined_pwd)):
            combined_pwd[i] = 0

    input("Press Enter to continue...")


def decrypt_with_dialog():
    clear_screen()
    print("=== DECRYPTING VIA FILE DIALOG ===")
    file1, file2 = select_files_for_decryption()
    if not file1 and not file2:
        print("No file selected (or dialog canceled)!")
        input("\nPress Enter to continue...")
        return

    print("Select authentication method for decryption:")
    combined_pwd, _ = choose_auth_method()

    enc_file = None
    meta_file = None
    possible_files = [file1, file2]
    for p in possible_files:
        if p and p.endswith(".enc"):
            enc_file = p
        elif p and p.endswith(".meta"):
            meta_file = p

    try:
        if enc_file:
            folder, filename = os.path.split(enc_file)
            if meta_file and os.path.dirname(meta_file) != folder:
                print(f"Note: The metadata (.meta) is in a different folder ({meta_file}).")
            decrypt_file(filename, combined_pwd)
        else:
            print("No valid .enc file identified for decryption.")
    except Exception as e:
        print(f"Decryption failed: {e}")
    finally:
        for i in range(len(combined_pwd)):
            combined_pwd[i] = 0

    input("\nPress Enter to continue...")


def encryption_options_menu():
    """
    Submenu for Encryption Options.
    """
    while True:
        clear_screen()
        print("=== ENCRYPTION OPTIONS ===")
        print("""
[1] Encrypt Text
[2] Open File Selection Window
[3] Decrypt File
[4] Encrypt Multiple Files
[0] Back
        """)
        choice = input("Select an option: ").strip().lower()
        if choice == '1':
            encrypt_text()
        elif choice == '2':
            menu_file_dialog()
        elif choice == '3':
            decrypt_menu()
        elif choice == '4':
            encrypt_multiple_files()
        elif choice == '0':
            break
        else:
            print("Invalid option!")
            time.sleep(1)


def encrypted_file_settings_menu():
    """
    Submenu for Encrypted File Settings.
    """
    while True:
        clear_screen()
        print("=== ENCRYPTED FILE SETTINGS ===")
        print("""
[1] Generate Ephemeral Token
[2] Create Hidden Volume (Plausible Deniability)
[3] Re-Encrypt (Key Rolling) - (for normal volumes)
[4] Change Real Volume Password (Hidden)
[0] Back
        """)
        choice = input("Select an option: ").strip().lower()
        if choice == '1':
            generate_ephemeral_token_menu()
        elif choice == '2':
            try:
                encrypt_hidden_volume()
            except Exception as e:
                print(f"Failed to create hidden volume: {e}")
            input("\nPress Enter to continue...")
        elif choice == '3':
            reencrypt_file()
        elif choice == '4':
            change_real_volume_password()
        elif choice == '0':
            break
        else:
            print("Invalid option!")
            time.sleep(1)


def main_menu():
    """
    Main CLI menu for CryptGuard, offering two tabs:
    [1] Encryption Options and [2] Encrypted File Settings.
    """
    while True:
        clear_screen()
        folder = os.path.join(os.path.expanduser("~"), "Documents", "Encoded_files_folder")
        try:
            os.makedirs(folder, exist_ok=True)
        except OSError as e:
            print(f"Warning: Could not create folder for encrypted files: {e}")

        print("=== CRYPTGUARD - ADVANCED ENCRYPTION SYSTEM ===")
        print("""
[1] Encryption Options
[2] Encrypted File Settings
[0] Exit
        """)
        choice = input("Select an option: ").strip().lower()
        if choice == '1':
            encryption_options_menu()
        elif choice == '2':
            encrypted_file_settings_menu()
        elif choice == '0':
            print("Exiting...")
            time.sleep(1)
            break
        else:
            print("Invalid option!")
            time.sleep(1)


if __name__ == "__main__":
    main_menu()
