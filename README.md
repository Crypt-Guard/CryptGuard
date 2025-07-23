# 🔐 CryptGuard v2 – Version 2.6.2 (July 2025)

**CryptGuard v2** is a **modern**, **cross‑platform**, and **user‑friendly** file‑encryption suite. It blends state‑of‑the‑art cryptography (AES‑256‑GCM, XChaCha20‑Poly1305) with hardened key management, memory‑safety primitives, and a sleek Qt‑based interface.

---

## ✨ Key Features

| #  | Capability                   | Details                                                                                                 |
| -- | ---------------------------- | ------------------------------------------------------------------------------------------------------- |
| 1  | **Authenticated Encryption** | AES‑256‑GCM, ChaCha20‑Poly1305, or **XChaCha20‑Poly1305** (24‑byte random nonce).                       |
| 2  | **Argon2id KDF – Profiles**  | *Fast*, *Balanced* (default), or *Secure* \| auto‑calibration (`--calibrate-kdf`).                      |
| 3  | **HKDF‑Salted Key Split**    | Single HKDF‑SHA256 call ⇢ 32 B `enc_key` ‖ 32 B `hmac_key` (salt = Argon2 salt).                        |
| 4  | **Smart Modes**              | < 10 MiB → single‑shot; ≥ 100 MiB → **streaming** with multithreaded chunk‑pipeline.                    |
| 5  | **Integrity & Redundancy**   | Global HMAC‑SHA256 (post‑v2.6 fix) + optional Reed–Solomon parity per chunk.                            |
| 6  | **Encrypted Metadata**       | File name + crypto params sealed with ChaCha20‑Poly1305.                                                |
| 7  | **Secure Memory**            | `SecureBytes` (mlock/VirtualLock + multi‑pass zeroize) & `KeyObfuscator` hardened with `ctypes.memset`. |
| 8  | **Rate‑Limiter**             | Exponential delay per file (SQLite) to thwart brute‑force attacks.                                      |
| 9  | **Process Hardening**        | DEP, anti‑debug, no core‑dump (`--harden`) on Windows; sandbox hints on Linux.                          |
| 10 | **Polished GUI**             | Drag‑&‑drop • password strength meter • Cancel button • secure‑delete toggle • progress bar w/ speed.   |
| 11 | **Time-Limited Encryption**  | Set expiration dates for encrypted files; files become undecryptable after the deadline.                |

---

## 🆕 What’s New in v2.6.2

| Area           | Change                                                                                             |
| -------------- | -------------------------------------------------------------------------------------------------- |
| **Integrity**  | ✅ **Unified HKDF** across all back‑ends (AES/ChaCha/XChaCha/CTR) – verification bug fixed.         |
| **Security**   | HKDF now receives the **same 16 B Argon2 salt**, strengthening the *extract* phase.                |
| **Memory**     | `KeyObfuscator.clear()` now zeroes native buffers via `ctypes.memset`.                             |
| **Robustness** | Atomic file finalisation with `os.replace()`; clearer SecurityWarnings accept `str` or `Severity`. |
| **Docs**       | Totally revamped README, updated architecture diagram & usage examples.                            |
| **New Feature** | ✨ **Time-Limited Encryption**: Set expiration dates for encrypted files, rendering them undecryptable post-deadline. |

---

## ✨ New Feature: Time‑Limited Encryption (File Expiration)

CryptGuard now lets you **set an expiration date for any encrypted file**. After the chosen deadline, the file becomes undecryptable, and any attempt to tamper with the date corrupts the file instantly.

### 1. How It Works ⚙️

| Step | Mechanism | Security Benefit |
|------|-----------|------------------|
| 1 | **Timestamp Captured** | `expires_at` (Unix UTC) is injected into the metadata JSON. Timestamp is immutable. |
| 2 | **AEAD Protection** | The entire JSON (incl. `exp`) is encrypted & authenticated with **XChaCha20‑Poly1305 / ChaCha20‑Poly1305 / AES‑GCM**. If any byte changes, the MAC fails → `InvalidTag`. |
| 3 | **Key Derivation Binds to Date** | File-key = `Argon2id(master‑key ‖ expires_at)`. Even if someone flips the date, the key no longer matches the MAC. |
| 4 | **Decrypt / Verify Gate** | `check_expiry()` blocks decryption when `now() > expires_at`. Ensures files “self‑lock” after the deadline. |

**Result**: Changing the date, header, or ciphertext without the password destroys the file. Only re‑encrypting with the correct password can create a new valid deadline.

### 2. Using the Feature 🚀

#### 2.1 GUI (main_app)

1. In the **main window**, select **Algorithm** & **Security profile** as usual.
2. Tick **Enable expiration date**.
3. Pick a day in the new **Expiration date** field (calendar popup).
   - Default = today (minimum); leaving the box disabled means *no expiration*.
4. Encrypt.
   - *Hover‑tooltip shows the chosen UTC timestamp.*

#### 2.2 CLI (cryptguard enc)

```bash
cryptguard enc --expires "+30d" file.txt
cryptguard enc --expires "2025‑12‑31T23:59:59Z" secrets.zip
```

- `--expires "+Nd"` accepts `+7d`, `+12h`, `+90m`, etc.
- Omit `--expires` for perpetual encryption.

### 3. Backward Compatibility ♻️

- **Old files** (without `exp`) still open normally.
- **Old scripts / APIs**: The new parameter `expires_at` has a default of `None`; nothing breaks.
- **Verify‑only mode** now fails with `ExpiredFileError` when the deadline is past.

### 4. Limitations & Notes 📌

- Relies on the host clock. Add NTP/TSA enforcement for stronger anti‑rollback.
- “Expiration” *denies access*; it does **not** shred the payload. Use `cryptguard purge --expired` for auto‑deletion.
- A user with the password can always re‑encrypt a local plaintext copy—they just can’t change the deadline on the existing `.enc`.

---

## 🚀 Getting Started

### 1) Ready‑to‑Use Executable (Windows)

1. Download the latest `CryptGuard.exe` from the **Releases** tab.
2. Double‑click or launch from a console:

```bash
CryptGuard.exe
```

### 2) Run from Source (Python 3.11+)

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

### 🔑 CLI Quick Start

```bash
# Argon2 calibration (~0.5 s target)
python -m crypto_core --calibrate-kdf

# Enable hardening
python -m crypto_core --harden

# Encrypt a file (auto‑detects optimum mode)
python -m crypto_core encrypt path/to/file.pdf

# Encrypt with expiration
python -m crypto_core encrypt --expires "+30d" path/to/file.pdf

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
 │   ├─ file_crypto_xchacha_stream.py
 │   └─ tamper_expire.py
 ├─ assets/cryptguard.ico
 └─ main_app.py                   # PySide6 launcher
```

---

## ⚠️ Security Best Practices

- Choose passphrases ≥ 4 random words or ≥ 12 high‑entropy characters.
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

CryptGuard v2 is distributed under the **Apache License 2.0**.  
Use at your own risk; no warranties expressed or implied.

---

## 🙏 Acknowledgments

- **argon2‑cffi** – password hashing & KDF
- **cryptography** – AES & ChaCha primitives
- **PySide6 / Qt** – cross‑platform GUI
- **reedsolo** – Reed–Solomon codec
- **zxcvbn‑python** – password strength meter

> *Stay safe & encrypt everything.*
