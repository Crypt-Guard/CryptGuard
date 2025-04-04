# 🔐 CryptGuard

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-audited-green.svg)](SECURITY.md)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

CryptGuard is an **advanced encryption solution** focused on **security** and **usability**. It provides robust file encryption (single-shot and streaming), hidden volumes with plausible deniability, and modern key derivation via Argon2id.

---

## ✨ Key Features

1. **Authenticated Encryption**  
   - Uses ChaCha20-Poly1305 to ensure confidentiality and integrity in a single operation.

2. **Argon2id Key Derivation**  
   - Secure password hashing and fallback handling if system memory is insufficient.
   - Optional combination of password + key file for enhanced entropy.

3. **Multiple Encryption Modes**  
   - **Single-Shot** for small or moderate files.  
   - **Streaming** mode for large files, reading data in chunks without excessive RAM usage.

4. **Hidden Volumes (Plausible Deniability)**  
   - Create “decoy” and “real” volumes within the same encrypted file, each with separate passwords.
   - Real volume also requires an ephemeral token, preventing accidental or forced disclosure.

5. **Metadata Encryption**  
   - Double-layer metadata encryption, written atomically (prevents corruption on failure).
   - Stores original file extension and Argon2 parameters securely.

6. **Reed-Solomon Error Correction**  
   - Optionally corrects minor corruption, preserving data in unreliable storage scenarios.

7. **Key Rolling**  
   - Allows re-encryption of a normal (non-hidden) volume with a new password, removing the old encryption key.

8. **Now Available as a Single Executable**  
   - You can download the `.exe` file from the Releases section for a simpler, no-install experience on Windows.

---

## 🔖 Recent Updates

- **Removed plaintext checksums** to eliminate any leakage of SHA-256 hashes of unencrypted data.
- **Argon2id fallback** if `MemoryError` occurs, making it more adaptable on systems with limited RAM.
- **Atomic metadata write** with temporary files to avoid corruption if interrupted.
- **Enhanced streaming** to handle large files both in encryption and decryption, reading incrementally.
- **Improved error handling**: automatically removes incomplete `.enc` or temporary files on failures.
- **Sensitive data cleared from memory** (`password` and `derived_key` zeroized post-operation).
- **Hidden volumes** refined: ephemeral token usage, two-layer structure, and better handling of decoy vs. real volume.
- **Packaged as a single `.exe`** for Windows users, simplifying installation and execution.

---

## 🚀 Getting Started

### 1) Download & Run (Executable Release)

1. Go to the [Releases](../../releases) page of this repository.
2. Find and download the `CryptGuard.exe` (or similarly named `.exe` file).
3. Place it in a convenient folder. Double-click to run on Windows.

**No Python installation required** when using the `.exe`.  
For advanced usage, open a Command Prompt or PowerShell in that folder and run:

```bash
CryptGuard.exe
```

This approach is especially handy if you prefer using it in a CLI manner.  

> **Note**: Windows SmartScreen or antivirus software may show warnings because this is an unsigned executable. You can accept or whitelist it if you trust the source.

---

### 2) Running from Source (Optional)

If you prefer Python or want to modify the code:

1. **Clone** the repository:
   ```bash
   git clone https://github.com/Crypt-Guard/CryptGuard.git
   cd CryptGuard
   ```
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Run**:
   ```bash
   python main.py
   ```

You will need Python 3.8+ installed. This mode also lets you adjust Argon2 parameters or make custom modifications.

---

## 🔑 Usage Overview

1. **Encrypt a File**  
   - Specify a password (confirm it).  
   - For large files, CryptGuard automatically suggests streaming mode to avoid high RAM usage.

2. **Decrypt a File**  
   - Supply the same password used at encryption.  
   - The file recovers its original extension, as stored in metadata.

3. **Hidden Volumes**  
   - Protect real data inside a single encrypted container.  
   - Present a decoy password if coerced; only the correct real password + ephemeral token reveals the real content.

4. **Key Rolling**  
   - Decrypt a normal volume with the old password.  
   - Re-encrypt with a new password, optionally removing the old .enc files.

5. **Error Correction**  
   - Reed-Solomon adds 32 bytes parity to help recover from minor corruptions.  
   - Can be toggled globally in the config or recognized in metadata for consistent usage.

---

## ⚠️ Security & Safety Notes

- **Password Strength**  
  - Choose strong passwords. Argon2id helps defend against brute force, but a weak password is still a risk.
- **Ephemeral Token** (Hidden Volume)  
  - Keep the ephemeral token secret; losing it makes the real volume inaccessible even with the correct password.
- **Backups**  
  - Regularly back up your `.enc` file **and** its `.meta`, or you might permanently lose access if the files get corrupted beyond correction.
- **Memory Usage**  
  - If you see `MemoryError`, CryptGuard attempts a fallback approach with lower Argon2 memory_cost. If that fails repeatedly, reduce parameters or use a more capable system.
- **Signed Executables**  
  - Currently, the `.exe` is not code-signed. Some antivirus software or SmartScreen might flag or prompt. Confirm the source or build from source if in doubt.

---

## 🏗️ Project Structure

```
CryptGuard/
 ┣━━ main.py
 ┣━━ config.py
 ┣━━ chunk_crypto.py
 ┣━━ single_shot.py
 ┣━━ streaming.py
 ┣━━ hidden_volume.py
 ┣━━ metadata.py
 ┣━━ password_utils.py
 ┣━━ rs_codec.py
 ┣━━ argon_utils.py
 ┣━━ utils.py
 ┗━━ README.md
```

- **main.py**: primary entry point (CLI).  
- **hidden_volume.py**: logic for hidden (decoy + real) volume creation.  
- **streaming.py**: encrypt/decrypt in chunks.  
- **argon_utils.py**: Argon2id-based key derivation with fallback.  
- **metadata.py**: encryption of `.meta` with double-layer approach.

---

## 🤝 Contributing

Contributions to CryptGuard are welcome! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute:

- **Bug Reports**: Submit an Issue.  
- **Pull Requests**: Fork, commit, and open a PR.  
- **Security Issues**: Check [SECURITY.md](SECURITY.md) for guidelines.

---

## 📜 License

CryptGuard is licensed under the [Apache 2.0 License](LICENSE).  

Use it responsibly; **no warranty** is provided for potential data loss or misuse.

---

## 🏆 Acknowledgments

- The Argon2id KDF is provided by `argon2-cffi`.  
- Encryption powered by Python’s `cryptography` library with ChaCha20-Poly1305.  
- Reed-Solomon implemented via `reedsolo`.  
- Special thanks to all contributors who have helped improve CryptGuard’s security and usability.

---

**CryptGuard** – Advanced Encryption. Secure. Modern. Tested. Enjoy!
