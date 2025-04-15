# 🔐 CryptGuard – Version 1.1.0

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-audited-green.svg)](SECURITY.md)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

CryptGuard is an **advanced encryption solution** focused on **security** and **usability**. It provides robust file encryption (single-shot and streaming), hidden volumes with plausible deniability, Argon2id-based password hashing, and memory protection enhancements like obfuscated keys and secure zeroization.

---

## ✨ Key Features

1. **Authenticated Encryption**  
   - Uses ChaCha20-Poly1305 for confidentiality and integrity.

2. **Argon2id Key Derivation**  
   - Modern and secure password hashing with fallback handling if system memory is limited.
   - Optional combination of password + key file for stronger entropy.

3. **Multiple Encryption Modes**  
   - **Single-Shot** for small or moderate files – now optionally supports *sub-chunk re-obfuscation*, reducing key exposure in memory.  
   - **Streaming** for large files, processing data in chunks without excessive memory usage.

4. **Hidden Volumes**  
   - Creates “decoy” and “real” volumes within a single encrypted file (plausible deniability).  
   - The real volume requires an ephemeral token in addition to the password for enhanced secrecy.

5. **Metadata Encryption & Double Layer**  
   - Outer and inner metadata encryption to protect Argon2 parameters, salts, and original file info.  
   - Optionally sign metadata with HMAC to detect tampering.

6. **Reed-Solomon Error Correction**  
   - Optional correction of minor corruptions in `.enc` files, ideal for unreliable storage.

7. **Key Rolling**  
   - Re-encrypt a normal volume under a new password, effectively discarding the old key.

8. **Secure Memory Handling**  
   - In-memory keys are **obfuscated** (via XOR masking) and stored in `SecureBytes` containers to facilitate zeroization.  
   - Passwords are never kept in plain form longer than necessary.

---

## 🆕 What’s New in v1.1.0

- **Module Segregation**:  
  - All cryptographic logic now resides in the `crypto_core/` folder (key derivation, chunk encryption, streaming, etc.), separating it from user-facing logic.  
  - Makes auditing and maintenance simpler.
  
- **Re-Obfuscation for Single-Shot “Medium” Files**:  
  - Files that do not trigger streaming but exceed a configurable threshold are now split into sub-chunks in memory.  
  - The key is re-obfuscated after each sub-chunk, reducing the time in which it remains in cleartext in RAM.

- **`multi_sub_block` Mode**:  
  - If single-shot encrypts multiple sub-chunks, the `.meta` indicates `multi_sub_block = true`, and `decrypt_data_single()` automatically processes them in a loop.

- **Refined Memory Security**:  
  - `KeyObfuscator` is used consistently, ensuring minimal exposure of derived keys.  
  - Passwords and ephemeral tokens stored via `SecureBytes` are explicitly wiped after use.

- **Improved Hidden Volume Flow**:  
  - Double-layer outer/inner metadata encryption.  
  - Ephemeral token handling is integrated into the new memory-wiping logic.

---

## 🚀 Getting Started

### 1) Using the Pre-Built Executable (Windows)

1. Download `CryptGuard.exe` from the latest [Releases](../../releases).
2. Place it in any folder, then run by double-clicking or from a terminal:
   ```bash
   CryptGuard.exe
   ```
3. No Python installation required. You may see SmartScreen warnings due to an unsigned binary; accept/trust if you know the source.

### 2) Running from Source (Python 3.8+)

1. **Clone** the repository:
   ```bash
   git clone https://github.com/Crypt-Guard/CryptGuard.git
   cd CryptGuard
   ```
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Launch**:
   ```bash
   python main.py
   ```
You can tweak Argon2 parameters or adjust chunk sizes in `crypto_core/config.py`.

---

## 🔑 Typical Usage Scenarios

1. **Encrypt a File**  
   - Choose single-shot or streaming automatically based on file size.  
   - Password can be combined with a key file if desired.  
   - Optionally specify sub-chunk re-obfuscation thresholds for single-shot in `config.py`.

2. **Decrypt a File**  
   - Provide the correct password (and key file if used).  
   - If sub-chunk or streaming mode was used, CryptGuard seamlessly handles multi-block data.

3. **Hidden Volumes**  
   - Store decoy data + real data in a single `.enc`.  
   - Present a decoy password to reveal only the dummy content; real volume requires the ephemeral token and real password.

4. **Key Rolling**  
   - Decrypt a normal `.enc` with the old password, then re-encrypt with a new one.  
   - Optionally remove the old `.enc` and `.meta` files.

5. **Reed-Solomon**  
   - For slightly corrupted files, this can salvage data if parity is sufficient.

---

## 🗂️ Project Structure

```text
my_project/
 ├─ crypto_core/
 │   ├─ __init__.py
 │   ├─ config.py
 │   ├─ secure_bytes.py
 │   ├─ key_obfuscator.py
 │   ├─ argon_utils.py
 │   ├─ rs_codec.py
 │   ├─ chunk_crypto.py
 │   ├─ metadata.py
 │   ├─ single_shot.py
 │   ├─ streaming.py
 │   └─ utils.py
 ├─ main.py
 ├─ hidden_volume.py
 ├─ password_utils.py
 ├─ file_chooser.py
 └─ README.md
```

- **`crypto_core/`**: Core cryptographic logic (key derivation, chunk encryption, streaming, secure memory handling).
- **`hidden_volume.py`**: Creates/deciphers hidden volumes (decoy + real).
- **`main.py`**: CLI interface, menu-driven usage.
- **`password_utils.py`**: Gathers user passwords, validates, and optionally uses a key file.

---

## ⚠️ Security Recommendations

- **Strong Passwords**: Argon2id provides robust derivation, but the ultimate security depends on the user-chosen password strength.
- **Ephemeral Token**: Keep it secret for real hidden volumes. Lost tokens make the real data unrecoverable.
- **Backup**: Save both `.enc` and `.meta` files. Corruption beyond Reed-Solomon’s ability can lead to permanent data loss.
- **Verify Source**: The `.exe` is unsigned; build from source or check authenticity if in doubt.

---

## 🤝 Contributing

1. Fork this repository.  
2. Make changes and add tests.  
3. Submit a Pull Request.  
   - For bug reports or suggestions, open an **Issue**.  
   - Follow [CONTRIBUTING.md](more_info/CONTRIBUTING.md) guidelines.

---

## 📜 License & Disclaimer

- Licensed under the [Apache 2.0 License](LICENSE).  
- Use responsibly; **no warranty** is offered for data mishandling or misuse.

---

## 🙏 Acknowledgments

- [argon2-cffi](https://pypi.org/project/argon2-cffi/) for Argon2id.  
- [cryptography](https://pypi.org/project/cryptography/) for ChaCha20-Poly1305.  
- [reedsolo](https://pypi.org/project/reedsolo/) for Reed-Solomon capabilities.  
- Everyone contributing to a more secure CryptGuard experience.

---

**CryptGuard** – Secure, Modern, and Flexible Encryption for Everyone.
