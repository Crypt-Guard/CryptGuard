# 📜 CryptGuard Update Notes

**Version:** 1.0.1 (Pending)  
**Date:** April 2025  

---

## 🚀 Summary of Changes

This update introduces major improvements to the CryptGuard security model, focusing on better memory protection for sensitive data such as passwords and cryptographic keys.  
The update significantly enhances defense against physical attacks like **cold boot attacks** by minimizing the exposure of secrets in RAM.

---

## 🔒 Secure Memory Management

### ➤ **New `SecureBytes` Class**
- Introduced a unified `SecureBytes` implementation for secure handling of sensitive information (passwords, keys, tokens).
- `SecureBytes` stores data in a **mutable** `bytearray`, allowing explicit overwriting of memory (zeroization) after use.
- Provides `.clear()` and `.wipe()` methods to securely erase contents when no longer needed.
- All user passwords are now stored and manipulated using `SecureBytes`, replacing insecure use of plain strings or bytes.

### ➤ **New Secure Utilities**
- **`secure_password_prompt()`**: Securely prompts for a password, immediately wrapping it in `SecureBytes`.
- **`secure_string_to_bytes()`**: Converts any string into a protected `SecureBytes` object.
- **`wipe_sensitive_data()`**: Utility function to securely erase bytearrays or sensitive variables.

---

## 🧩 Key Obfuscation

### ➤ **New `KeyObfuscator` Class**
- Immediately obfuscates any derived cryptographic key in memory by applying random XOR masking and fragmentation.
- The original key is wiped after obfuscation.
- Keys are only **deobfuscated temporarily** during encryption/decryption operations, then wiped again.
- Adds resistance against memory analysis and cold boot attacks by making the reconstruction of keys in RAM far more difficult.

---

## 🔑 Secure Key Derivation

### ➤ **Argon2-Based Key Derivation Enhancement**
- Passwords are passed as `SecureBytes` into the Argon2id key derivation function.
- After key derivation:
  - The key is encapsulated into `SecureBytes`.
  - Immediately obfuscated using `KeyObfuscator`.
- Memory fallback support: If a `MemoryError` occurs during Argon2, memory parameters are halved to maintain usability with warnings.

---

## 📦 Metadata Protection

### ➤ **Double Encryption Layer for Metadata**
- Metadata (salts, Argon2 parameters, configuration flags) are now encrypted twice:
  - Inner Layer: Encrypted with a key derived from the real password.
  - Outer Layer: Encrypted with a key derived from the decoy password (for hidden volumes).
- Keys for metadata encryption are handled using the new `SecureBytes` and `KeyObfuscator` mechanisms.
- Keys are **wiped immediately** after encrypting/decrypting.

---

## 🗂️ File Encryption/Decryption Updates

### ➤ **Single-Shot and Streaming Modes**
- In both modes:
  - Passwords are handled securely as `SecureBytes`.
  - Keys are derived, obfuscated, deobfuscated temporarily for each operation, and wiped afterward.
  - In streaming mode, keys are **re-obfuscated between chunks** to minimize clear-text key exposure during long operations.
- All sensitive objects are explicitly cleared inside `finally` blocks, even in case of errors or interruptions.

---

## 🛡️ Hidden Volume Enhancements

### ➤ **Full Security for Decoy and Real Passwords**
- Decoy and real passwords for hidden volumes are collected as `SecureBytes`.
- Real volume tokens are stored and wiped securely.
- After volume creation or password change:
  - Passwords and tokens are securely wiped from memory.
  - Metadata for decoy and real volumes are encrypted using protected and obfuscated keys.

---

## ⚙️ Configuration Improvements

- **New Configuration Constants:**
  - `RS_PARITY_BYTES`: Configurable number of Reed-Solomon parity bytes.
  - `META_VERSION`: Metadata format version control.
  - `SIGN_METADATA`: Option to sign metadata for integrity.

- **Reed–Solomon Encoding (rs_codec.py):**
  - Updated to use the configurable `RS_PARITY_BYTES` instead of hardcoded values.

---

## ⚠️ Critical Security Fixes

- **Passwords and keys are never left in memory** after use.
- **Cryptographic keys are never stored contiguously** in RAM without obfuscation.
- **Explicit zeroization** is enforced in all critical paths (passwords, tokens, derived keys).
- **Metadata encryption** follows a **layered** protection model.

---

## 📈 Impact

| Aspect                  | Old Version                    | Updated Version                |
|--------------------------|---------------------------------|---------------------------------|
| Memory Protection        | No zeroization / static keys    | SecureBytes + KeyObfuscation    |
| Key Exposure             | Clear-text keys in memory       | Temporary deobfuscation only    |
| Metadata Security        | Single-layer encryption         | Double-layer encryption         |
| Hidden Volumes           | Basic implementation            | Full hidden password protection |
| Cold Boot Resistance     | Weak                            | Stronger (fragmented key storage) |

---

## 📝 Final Remarks

This update makes CryptGuard **far more resilient** against physical memory attacks such as cold boot attacks, forensic RAM analysis, and other advanced extraction techniques.  
It sets a new standard for how sensitive data should be handled in memory and provides a much stronger security foundation for future improvements.
