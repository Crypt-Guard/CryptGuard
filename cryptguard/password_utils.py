# password_utils.py

import os
import sys
import hashlib
import string
import getpass

try:
    from zxcvbn import zxcvbn
except ImportError:
    print("Please install zxcvbn-python: pip install zxcvbn-python")
    sys.exit(1)

def validate_password(pwd: str) -> bool:
    """
    Ensures the password has at least 8 characters, containing lowercase, uppercase,
    digits, special characters and a zxcvbn score >= 3.
    """
    if len(pwd) < 8:
        print("Password must have at least 8 characters.")
        return False
    if not any(c.islower() for c in pwd):
        print("Password must contain at least one lowercase letter.")
        return False
    if not any(c.isupper() for c in pwd):
        print("Password must contain at least one uppercase letter.")
        return False
    if not any(c.isdigit() for c in pwd):
        print("Password must contain at least one digit.")
        return False
    if not any(c in string.punctuation for c in pwd):
        print("Password must contain at least one special character.")
        return False

    score = zxcvbn(pwd)['score']
    if score < 3:
        print("Weak password. Please choose a more complex one.")
        return False
    return True

def get_file_hash(file_path):
    """
    Returns (bytes_digest, hexdigest) of the specified file.
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
        print("Error reading the key file.")
        return None, None

def validate_key_file(expected_hash: str) -> bool:
    """
    Asks for the key file path and validates its SHA-256 hash.
    """
    key_file_path = os.path.normpath(input("Enter the key file path for validation: ").strip())
    if not os.path.exists(key_file_path):
        print("Key file not found!")
        return False
    with open(key_file_path, 'rb') as f:
        data = f.read()
    computed_hash = hashlib.sha256(data).hexdigest()
    if computed_hash != expected_hash:
        print("Invalid key file!")
        return False
    return True

def get_combined_password():
    """
    Asks for the password (with confirmation) and, optionally, a key file.
    Returns a combination (bytearray) and the key file hash if used.
    Note: Due to Python string immutability, complete clearing of password memory is limited.
    """
    while True:
        pwd1 = getpass.getpass("Enter password: ")
        if not validate_password(pwd1):
            print("Weak or invalid password, try again.")
            continue
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd1 != pwd2:
            print("Passwords do not match, try again.")
            continue
        break

    password_bytes = bytearray(pwd1.encode())
    use_key_file = input("Do you want to use a key file? (y/n): ").strip().lower()
    key_file_bytes = bytearray()
    key_file_hash = None
    if use_key_file == 'y':
        key_file_path = os.path.normpath(input("Key file path: ").strip())
        if os.path.exists(key_file_path):
            key_file_digest, key_file_hash = get_file_hash(key_file_path)
            if key_file_digest is not None:
                key_file_bytes = bytearray(key_file_digest)
            else:
                print("Error processing key file. Using password only.")
        else:
            print("Key file not found. Using password only.")

    combined = password_bytes + key_file_bytes
    # Clear sensitive variables
    pwd1 = "0" * len(pwd1)
    pwd2 = "0" * len(pwd2)
    for i in range(len(password_bytes)):
        password_bytes[i] = 0
    for i in range(len(key_file_bytes)):
        key_file_bytes[i] = 0

    return combined, key_file_hash

def get_single_password():
    """
    Asks for a password (without key file).
    """
    while True:
        pwd1 = getpass.getpass("Enter password (password only): ")
        if not validate_password(pwd1):
            print("Weak or invalid password, try again.")
            continue
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd1 != pwd2:
            print("Passwords do not match, try again.")
            continue
        break
    password_bytes = bytearray(pwd1.encode())
    pwd1 = "0" * len(pwd1)
    pwd2 = "0" * len(pwd2)
    return password_bytes

def choose_auth_method():
    """
    Allows the user to choose between:
    [1] Password + key file
    [2] Password only
    Returns (combined authentication as bytearray, key file hash if any).
    """
    print("\nSelect authentication method:")
    print("[1] Password + key file")
    print("[2] Password only")
    choice = input("Choose: ").strip()
    if choice == '1':
        return get_combined_password()
    elif choice == '2':
        pwd = get_single_password()
        return pwd, None
    else:
        print("Invalid option, defaulting to password + key file.")
        return get_combined_password()
