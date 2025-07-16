# 🔐 CryptGuardv2 – Version 2.6.0  <sub>(July 2025)</sub>

[](https://www.google.com/search?q=LICENSE)
[](https://www.python.org/)
[](https://www.google.com/search?q=%23-security-recommendations)
[](https://www.google.com/search?q=CONTRIBUTING.md)

**CryptGuard v2** is a **modern** and **user-friendly** file encryption solution for Windows (macOS/Linux roadmap).
It combines **AES-256-GCM** and **ChaCha20-Poly1305**, derives keys with **Argon2id**, applies memory protection, optional Reed–Solomon, and a sleek PySide6 interface.

-----

## ✨ Key Features

1.  **Authenticated Encryption**

      * AES‑256‑GCM, ChaCha20‑Poly1305 **or XChaCha20‑Poly1305** (24‑byte nonce).

2.  **Argon2id KDF**

      * Profiles: **Fast**, **Balanced** (default), **Secure**.
      * Automatic calibration `--calibrate-kdf`.

3.  **Smart Encryption Modes**

      * **Single‑Shot** ≤ 10 MiB (AES / ChaCha / **XChaCha**).
      * **Streaming** ≥ 100 MiB with parallelism (AES, ChaCha, **XChaCha**).

4.  **Integrity & Redundancy**

      * Global HMAC-SHA256 over `.enc`.
      * **Reed–Solomon** (32 B) per chunk (optional).

5.  **Encrypted Metadata**

      * Salt + Nonce + ChaCha20-Poly1305 guarding the original name and parameters.

6.  **Secure Memory Handling**

      * `SecureBytes` (mlock/VirtualLock + zeroize).
      * `KeyObfuscator` (XOR-mask + timed exposure).

7.  **Local Rate-Limiter**

      * Exponential delay per file (`tries.db`) to mitigate brute-force.

8.  **Process Hardening** (Windows)

      * Permanent DEP, anti-debug, no core-dump (`--harden`).

9.  **User-Friendly GUI**

      * Drag‑&‑drop, confirm‑password, zxcvbn meter, **Cancel button**, single File/Folder dialog, 0–100% progress bar, locale‑aware speedometer, secure‑delete toggle.

10. **One-File Executable**

      * Build via PyInstaller `--onefile --windowed --icon cryptguard.ico`.

-----

## 🆕 What's New in v2.6.0

| Category             | Highlights                                                                 |
| -------------------- | -------------------------------------------------------------------------- |
| **Encryption**       | New **XChaCha20‑Poly1305** (single & streaming, 24 B random nonce).        |
| **UX**               | **Cancel** button, single picker, immediate progress feedback, speedometer.|
| **Performance**      | Zero-copy XChaCha streaming; chunk-by-chunk progress callback.             |
| **Security**         | ACL logging on Windows, SecureBytes `__del__`, secure-delete for folders.  |
| **Robustness**       | Rate-limit migrated to shared **SQLite**, auto-calibration prompt for Argon2. |

-----

## 🚀 Getting Started

### 1\) Ready-to-use Executable (Windows)

1.  Download `CryptGuard.exe` from the [Releases] tab.
2.  Run with a double-click **or** via the terminal:

<!-- end list -->

```bash
CryptGuard.exe
```

### 2\) Running from source code (Python 3.9+)

```bash
git clone https://github.com/Crypt-Guard/CryptGuard.git
cd CryptGuardv2
pip install -r requirements.txt
python main_app.py          # starts GUI
```

Fine-tuning (Argon2 profiles, chunk size) in `crypto_core/config.py`.

### 3\) Build one-file executable

```bash
pip install pyinstaller pillow
pyinstaller --onefile --windowed --icon cryptguard.ico main_app.py
```

### 🔑 Typical Usage (CLI)

```bash
# calibrate Argon2 for ~0.5s on your machine
python -m crypto_core --calibrate-kdf

# enable extra hardening
python -m crypto_core --harden

# encrypt
python -m crypto_core encrypt path/to/file.pdf

# decrypt
python -m crypto_core decrypt file.pdf.enc
```

-----

## 🗂️ Project Structure

```
CryptGuardv2/
 ├─ crypto_core/
 │   ├─ __init__.py
 │   ├─ config.py
 │   ├─ logger.py
 │   ├─ utils.py
 │   ├─ secure_bytes.py
 │   ├─ key_obfuscator.py
 │   ├─ argon_utils.py
 │   ├─ rs_codec.py
 │   ├─ metadata.py
 │   ├─ rate_limit.py
 │   ├─ security_warning.py
 │   ├─ process_protection.py
 │   ├─ kdf.py
 │   ├─ chunk_crypto.py
 │   ├─ file_crypto_ctr.py
 │   ├─ file_crypto.py
 │   ├─ file_crypto_chacha.py
 │   ├─ file_crypto_chacha_stream.py
 │   ├─ file_crypto_xchacha.py
 │   └─ file_crypto_xchacha_stream.py
 └─ main_app.py
```

-----

## ⚠️ Security Recommendations

  * Use strong passwords (phrases ≥ 4 words or ≥ 12 varied characters).
  * Back up `.enc` and `.meta` files to external media.
  * Enable `--harden` in sensitive environments.
  * For SSDs, secure-delete is better than nothing, but consider full-disk encryption.

-----

## 🤝 Contributing

Fork ➜ branch ➜ commits with pytest tests ➜ Pull Request.
See `CONTRIBUTING.md`.

-----

## 📜 License & Disclaimer

Apache 2.0 – see `LICENSE`.
No warranties; use at your own risk.

-----

## 🙏 Acknowledgments

argon2-cffi, cryptography, PySide6, reedsolo, psutil, zxcvbn-python.

<p><em>Stay safe &amp; encrypt everything.</em></p></body></html><!--EndFragment-->

**CryptGuard v2 – Secure • Modern • User-Friendly**
