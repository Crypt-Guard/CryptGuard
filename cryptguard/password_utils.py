# password_utils.py
"""
Utility functions for password handling, including strength validation and
optionally combining with a key file.
"""

import os
import hashlib
import string
import getpass
from crypto_core.secure_bytes import SecureBytes

try:
    from zxcvbn import zxcvbn
    ZXC_AVAILABLE = True
except ImportError:
    print("Warning: zxcvbn-python not installed. Advanced password strength check unavailable.")
    ZXC_AVAILABLE = False

def validate_password(password: str) -> bool:
    if len(password) < 8:
        print("Password too short.")
        return False
    if not any(c.islower() for c in password):
        print("Password must contain at least one lowercase letter.")
        return False
    if not any(c.isupper() for c in password):
        print("Password must contain at least one uppercase letter.")
        return False
    if not any(c.isdigit() for c in password):
        print("Password must contain at least one digit.")
        return False
    if not any(c in string.punctuation for c in password):
        print("Password must contain at least one special character.")
        return False

    if ZXC_AVAILABLE:
        score = zxcvbn(password)['score']
        if score < 3:
            print("Weak password. Please choose a more complex one.")
            return False
    else:
        print("Warning: Password strength library not available; skipping advanced check.")

    return True

def get_file_hash(file_path: str):
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
    key_file_path = os.path.normpath(input("Enter the key file path: ").strip())
    if not os.path.exists(key_file_path):
        print("Key file not found!")
        return False
    digest_bytes, key_file_hash = get_file_hash(key_file_path)
    if digest_bytes is None:
        print("Error processing key file. Using password only.")
        return False
    if key_file_hash != expected_hash:
        print("Invalid key file!")
        return False
    return True

def get_combined_password():
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

    password_bytes = SecureBytes(pwd1.encode())
    key_file_bytes = SecureBytes()
    key_file_hash = None

    use_key_file = input("Do you want to use a key file? (y/n): ").strip().lower()
    if use_key_file == 'y':
        key_file_path = os.path.normpath(input("Key file path: ").strip())
        if os.path.exists(key_file_path):
            digest_bytes, key_file_hash = get_file_hash(key_file_path)
            if digest_bytes is not None:
                key_file_bytes = SecureBytes(digest_bytes)
            else:
                print("Error processing key file. Using password only.")
        else:
            print("Key file not found. Using password only.")

    pwd1 = "0" * len(pwd1)
    pwd2 = "0" * len(pwd2)

    combined_secure = SecureBytes(password_bytes.to_bytes() + key_file_bytes.to_bytes())
    
    password_bytes.clear()
    key_file_bytes.clear()

    return combined_secure, key_file_hash

def get_single_password():
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
    
    password_bytes = SecureBytes(pwd1.encode())

    pwd1 = "0" * len(pwd1)
    pwd2 = "0" * len(pwd2)

    return password_bytes

def choose_auth_method():
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
