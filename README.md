# 🔐 CryptGuard – Version 1.2.0

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-audited-green.svg)](SECURITY.md)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

CryptGuard is an **advanced encryption solution** focused on **security** and **usability**. It provides robust file encryption (single-shot and streaming), hidden volumes with plausible deniability, Argon2id-based password hashing, customizable security profiles, and optimized parallel encryption.

---

## ✨ Key Features

1. **Authenticated Encryption**  
   - Uses ChaCha20-Poly1305 for confidentiality and integrity.

2. **Argon2id Key Derivation**  
   - Modern and secure password hashing with fallback handling if system memory is limited.
   - Optional combination of password + key file for stronger entropy.
   - Customizable Argon2 security profiles (Fast, Balanced, Secure).

3. **Optimized Encryption Modes**  
   - **Single-Shot** for small or moderate files – optionally supports *sub-chunk re-obfuscation*.
   - **Streaming** for large files, now optimized with parallel chunk processing and buffered I/O for enhanced performance.

4. **Hidden Volumes**  
   - Creates "decoy" and "real" volumes within a single encrypted file (plausible deniability).
   - The real volume requires an ephemeral token plus the password for enhanced secrecy.

5. **Metadata Encryption & Double Layer**  
   - Outer and inner metadata encryption protects Argon2 parameters, salts, and original file info.
   - Optionally sign metadata with HMAC to detect tampering.

6. **Reed-Solomon Error Correction**  
   - Optional correction of minor corruptions in `.enc` files.

7. **Key Rolling**  
   - Re-encrypt a normal volume under a new password, discarding the old key securely.

8. **Secure Memory Handling**  
   - Keys in memory are obfuscated (XOR masking) and stored securely.
   - Passwords and keys are explicitly zeroized after use.

---

## 🆕 What's New in v1.2.0

- **Parallel Chunk Processing**:
  - Multithreading significantly speeds up encryption, especially beneficial for large files.
  - Dynamic thread allocation based on file size (small: ≤4 threads, medium: ≤8, large: ≤12).

- **Buffered I/O**:
  - File read/write operations optimized to reduce disk bottlenecks.

- **Customizable Argon2 Security Profiles**:
  - **Fast**: Optimized for speed with minimal security overhead.
  - **Balanced** (default): Offers a balance between security and performance.
  - **Secure**: Maximizes security with higher computational resources.

- **Enhanced User Feedback**:
  - Added detailed progress bar and encryption speed indicators (MB/s).

- **Comprehensive English Documentation**:
  - All documentation and inline comments standardized in English.

---

## 🚀 Getting Started

### 1) Using the Pre-Built Executable (Windows)

1. Download `CryptGuard.exe` from the latest [Releases](../../releases).
2. Run from any folder by double-clicking or from a terminal:
   ```bash
   CryptGuard.exe
   ```

### 2) Running from Source (Python 3.8+)

```bash
git clone https://github.com/Crypt-Guard/CryptGuard.git
cd CryptGuard
pip install -r requirements.txt
python main.py
```
Adjust Argon2 profiles or chunk sizes in `crypto_core/config.py`.

---

## 🔑 Typical Usage Scenarios

- **Encrypt/Decrypt Files**: Automatically selects single-shot or streaming.
- **Hidden Volumes**: Store decoy and real data securely.
- **Key Rolling**: Update encrypted files with new passwords securely.

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

---

## ⚠️ Security Recommendations

- Use strong passwords and secure ephemeral tokens.
- Regularly backup encrypted files (`.enc` and `.meta`).

---

## 🤝 Contributing

- Fork the repository, make improvements, and submit a Pull Request.
- See [CONTRIBUTING.md](more_info/CONTRIBUTING.md) for guidelines.

---

## 📜 License & Disclaimer

- Licensed under the [Apache 2.0 License](LICENSE).
- No warranty provided for data mishandling or misuse.

---

## 🙏 Acknowledgments

- Thanks to libraries: `argon2-cffi`, `cryptography`, and `reedsolo`.

---

**CryptGuard** – Secure, Modern, and Flexible Encryption for Everyone.
