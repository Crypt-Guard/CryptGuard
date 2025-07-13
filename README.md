````markdown
# 🔐 CryptGuardv2

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)  
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)  
[![Security](https://img.shields.io/badge/security-hardening-green)]  

High-performance, memory-hardened file encryption tool for Windows (and soon macOS/Linux).  
Supports AES-GCM & ChaCha20-Poly1305, Argon2id KDF, robust GUI/CLI, secure delete, logging, and more.

---

## ✨ Key Features

- **Authenticated Encryption**  
  AES-256-GCM & ChaCha20-Poly1305 (single-shot & streaming)  
- **Argon2id KDF**  
  Memory-hard profiles (Fast, Balanced, Secure) + auto-calibration  
- **Memory Protection**  
  SecureBytes (mlock, zeroization), KeyObfuscator  
- **Integrity & Error-Correction**  
  HMAC-SHA256, optional Reed–Solomon per chunk  
- **Encrypted Metadata**  
  ChaCha20-Poly1305 guards file info, profiles & salts  
- **User-Friendly GUI**  
  Drag-&-drop, strength meter, confirm-password, progress bar  
- **Secure Delete**  
  Overwrite & remove original file safely  
- **CLI Support**  
  `--calibrate-kdf`, `--harden`, headless batch mode  
- **Logging & Testing**  
  RotatingFileHandler + SecureFormatter, pytest suite included  
- **One-file Executable**  
  Build with PyInstaller (`--onefile --windowed --icon cryptguard.ico`)

---

## 🚀 Quick Start

1. **Clone & Install**  
   ```bash
   git clone https://github.com/YourUser/CryptGuardv2.git
   cd CryptGuardv2
   pip install -r requirements.txt
````

2. **Run GUI**

   ```bash
   python main_app.py
   ```

3. **Run CLI**

   ```bash
   # Calibrate Argon2 for ~0.5 s derivation:
   python -m crypto_core --calibrate-kdf

   # Harden process (DEP, anti-debug):
   python -m crypto_core --harden

   # Encrypt a file:
   python -m crypto_core encrypt file.txt

   # Decrypt:
   python -m crypto_core decrypt file.txt.enc
   ```

4. **Build Executable**

   ```bash
   pip install pyinstaller pillow
   pyinstaller --onefile --windowed --icon cryptguard.ico main_app.py
   ```

---

## 📂 Repository Layout

```text
CryptGuardv2/
├─ crypto_core/
│  ├─ __init__.py
│  ├─ config.py
│  ├─ logger.py
│  ├─ utils.py
│  ├─ secure_bytes.py
│  ├─ key_obfuscator.py
│  ├─ argon_utils.py
│  ├─ rs_codec.py
│  ├─ metadata.py
│  ├─ rate_limit.py
│  ├─ security_warning.py
│  ├─ process_protection.py
│  ├─ kdf.py
│  ├─ chunk_crypto.py
│  ├─ file_crypto.py
│  ├─ file_crypto_chacha.py
│  └─ file_crypto_chacha_stream.py
├─ main_app.py
├─ cryptoguard.ico       # multi-res ICO file
├─ README.md
├─ ROADMAP.md
└─ requirements.txt
```

---

## 🤝 Contributing

1. Fork & clone
2. Create feature branch
3. Write tests (pytest)
4. Submit PR & await review

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## 📜 License

Licensed under **Apache 2.0**. See [LICENSE](LICENSE) for full text.

````
