# 🔐 CryptGuard v2 – Version 2.6.1  (July 2025)

&#x20;&#x20;

**CryptGuard v2** is a **modern**, **cross‑platform** and **user‑friendly** file‑encryption suite. It blends state‑of‑the‑art cryptography (AES‑256‑GCM, XChaCha20‑Poly1305) with hardened key management, memory‑safety primitives and a sleek Qt‑based interface.

---

## ✨ Key Features

| #  | Capability                   | Details                                                                                                 |
| -- | ---------------------------- | ------------------------------------------------------------------------------------------------------- |
| 1  | **Authenticated Encryption** | AES‑256‑GCM, ChaCha20‑Poly1305 or **XChaCha20‑Poly1305** (24‑byte random nonce).                        |
| 2  | **Argon2id KDF – Profiles**  | *Fast*, *Balanced* (default) or *Secure* \| auto‑calibration (`--calibrate-kdf`).                       |
| 3  | **HKDF‑Salted Key Split**    | Single HKDF‑SHA256 call ⇢ 32 B `enc_key` ‖ 32 B `hmac_key` (salt = Argon2 salt).                        |
| 4  | **Smart Modes**              | < 10 MiB → single‑shot; ≥ 100 MiB → **streaming** with multithreaded chunk‑pipeline.                    |
| 5  | **Integrity & Redundancy**   | Global HMAC‑SHA256 (post‑v2.6 fix) + optional Reed–Solomon parity per chunk.                            |
| 6  | **Encrypted Metadata**       | File name + crypto params sealed with ChaCha20‑Poly1305.                                                |
| 7  | **Secure Memory**            | `SecureBytes` (mlock/VirtualLock + multi‑pass zeroize) & `KeyObfuscator` hardened with `ctypes.memset`. |
| 8  | **Rate‑Limiter**             | Exponential delay per file (SQLite) to thwart brute‑force attacks.                                      |
| 9  | **Process Hardening**        | DEP, anti‑debug, no core‑dump (`--harden`) on Windows; sandbox hints on Linux.                          |
| 10 | **Polished GUI**             | Drag‑&‑drop • password strength meter • Cancel button • secure‑delete toggle • progress bar w/ speed.   |

---

## 🆕 What’s New in v2.6.1

| Area           | Change                                                                                             |
| -------------- | -------------------------------------------------------------------------------------------------- |
| **Integrity**  | ✅ **Unified HKDF** across all back‑ends (AES/ChaCha/XChaCha/CTR) – verification bug fixed.         |
| **Security**   | HKDF now receives the **same 16 B Argon2 salt**, strengthening the *extract* phase.                |
| **Memory**     | `KeyObfuscator.clear()` now zeroes native buffers via `ctypes.memset`.                             |
| **Robustness** | Atomic file finalisation with `os.replace()`; clearer SecurityWarnings accept `str` or `Severity`. |
| **Docs**       | Totally revamped README, updated architecture diagram & usage examples.                            |

---

## 🚀 Getting Started

### 1) Ready‑to‑Use Executable (Windows)

1. Download the latest `CryptGuard.exe` from the **Releases** tab.
2. Double‑click or launch from a console:

```bash
CryptGuard.exe
```

### 2) Run from Source (Python 3.11+)

```bash
git clone https://github.com/Crypt-Guard/CryptGuard.git
cd CryptGuardv2
python -m venv .venv && source .venv/bin/activate  # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main_app.py         # starts GUI
```

### 3) Build One‑File Executable

```bash
pip install pyinstaller pillow
pyinstaller --onefile --windowed --icon assets/cryptguard.ico main_app.py
```

### 🔑 CLI Quick Start

```bash
# Argon2 calibration (~0.5 s target)
python -m crypto_core --calibrate-kdf

# Enable hardening
python -m crypto_core --harden

# Encrypt a file (auto‑detects optimum mode)
python -m crypto_core encrypt path/to/file.pdf

# Verify integrity without decrypting
python -m crypto_core verify file.pdf.enc

# Decrypt
python -m crypto_core decrypt file.pdf.enc
```

---

## 🗂️ Project Structure

```text
CryptGuardv2/
 ├─ crypto_core/
 │   ├─ __init__.py
 │   ├─ config.py
 │   ├─ logger.py
 │   ├─ utils.py
 │   ├─ secure_bytes.py
 │   ├─ hkdf_utils.py
 │   ├─ verify_integrity.py
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
 ├─ assets/cryptguard.ico
 └─ main_app.py                   # PySide6 launcher
```

---

## ⚠️ Security Best Practices

- Choose passphrases ≥ 4 random words or ≥ 12 high‑entropy characters.
- Back up `.enc` + `.meta` files to offline media.
- Enable *secure‑delete* on spinning disks (SSD still keeps remnants – prefer full‑disk encryption).
- Run `--harden` in hostile or production environments.
- Keep CryptGuardv2 and its dependencies up‑to‑date.

---

## 🤝 Contributing

1. Fork → new branch → implement feature / fix (with pytest tests).
2. Ensure `pre-commit run --all-files` passes.
3. Open a Pull Request describing **what** and **why**.

See **CONTRIBUTING.md** for coding style & signing guidelines.

---

## 📜 License & Disclaimer

CryptGuard v2 is distributed under the **Apache License 2.0**.\
Use at your own risk; no warranties expressed or implied.

---

## 🙏 Acknowledgments

- **argon2‑cffi** – password hashing & KDF
- **cryptography** – AES & ChaCha primitives
- **PySide6 / Qt** – cross‑platform GUI
- **reedsolo** – Reed–Solomon codec
- **zxcvbn‑python** – password strength meter

> *Stay safe & encrypt everything.*
