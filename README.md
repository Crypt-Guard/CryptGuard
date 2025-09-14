# 🔐 CryptGuard v3.0 (September 2025)

**CryptGuard** is a modern, security-first file-encryption app with a Qt (PySide6) GUI.
Version **3.0** introduces a simplified, auditable core that writes a single, next-gen format based on **XChaCha20-Poly1305 SecretStream** (libsodium/PyNaCl). It delivers authenticated streaming encryption, tamper detection from start to finish, and private metadata handling (original name/extension and true size are revealed only to the decryptor).

---

## ✨ Highlights (v3.0)

| # | Feature                                                 | What it does                                                                                                                                                                          |
| - | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 | **Single algorithm: XChaCha20-Poly1305 (SecretStream)** | Streaming AEAD with 24-byte nonces, per-frame authentication, and an authenticated end-marker. New encryptions always use this mode.                                                  |
| 2 | **Commitment to header (AAD)**                          | The stream header and KDF parameters are bound as **Associated Data**. Any header tampering breaks decryption.                                                                        |
| 3 | **Authenticated `FINAL` with metadata**                 | The final record carries authenticated JSON (e.g., `orig_name`, `orig_ext`, `pt_size`, `chunks`, `pad`) so decrypt can safely restore the original filename/extension and exact size. |
| 4 | **Argon2id KDF with profiles**                          | Auto-calibrated parameters. Two profiles: **Interactive** (faster) and **Sensitive** (slower/more RAM) for higher brute-force cost.                                                   |
| 5 | **Privacy-friendly size handling**                      | Optional **Pad size** up to **16 KiB** to coarsen size leakage without excessive bloat. True plaintext size is authenticated and enforced at decrypt.                                 |
| 6 | **Robust verify & integrity**                           | Bit-flips in header, data frames, or trailing garbage are detected; decryption fails cleanly with a clear error.                                                                      |
| 7 | **Polished GUI**                                        | Drag-and-drop, progress and speed readouts, **Verify** button, selectable KDF profile, **Pad size** selector, expiration field, logging.                                              |
| 8 | **Built-in Vault**                                      | Optional passphrase-protected store for your **already-encrypted** files; now also binds its header via AAD and uses secure logging.                                                  |
| 9 | **Integrated KeyGuard**                                 | Built-in secure password generator with entropy calculation, multiple character sets, and its own vault for storing password entries. Features a sidebar UI for easy access.          |
| 10| **Safe defaults & sane pins**                           | SecretStream via PyNaCl/libsodium; modern `cryptography` where applicable; defensive file I/O and best-effort OS hardening.                                                           |

---

## 🆕 What’s new in **3.0** (vs **2.7.0**)

**Core/Format**

* ✅ **Unified writer**: new files use **XChaCha20-Poly1305 SecretStream** exclusively.
* ✅ **Header as AAD**: the stream header + KDF params are authenticated (commitment property).
* ✅ **`TAG_FINAL` metadata**: authenticated JSON carries `orig_name`, `orig_ext`, `pt_size`, `chunks`, `pad`.
* ✅ **Automatic name/extension restore** on decrypt (no need to rename manually).
* ✅ **Padding ceiling reduced to 16 KiB** (better trade-off between size privacy and bloat).

**KDF & Profiles**

* 🔁 Profiles renamed/simplified: **Interactive** (fast) and **Sensitive** (robust).
* 🔧 Per-machine auto-calibration; parameters are stored in the header (not secret) and are authenticated.

**Vault**

* 🔐 Vault writes/opens binding the header via AAD; logging uses **SecureFormatter** (masks secrets).
* 🧱 Robustness tweaks (atomic I/O, better SQLite PRAGMAs where applicable).

**KeyGuard Integration**

* 🔑 **Integrated password generator**: cryptographically secure password generation with entropy calculation.
* 📊 **Multiple character sets**: numbers, letters, alphanumeric, and full punctuation support.
* 💾 **KeyGuard Vault**: dedicated vault for storing password entries with atomic storage and compression.
* 🎯 **Sidebar UI**: non-intrusive side panel that attaches to the main window for easy access.
* ⚡ **Rate limiting**: built-in protection against brute-force attempts on the KeyGuard vault.

**Compatibility**

* 📖 **Backward-compatible reads**: older files (v1–v4) remain **readable**.
* ✍️ **Writes**: always the new v5 format (SecretStream).
* 🧩 On older decrypters, re-encrypt to gain the new protections.

> Note: the **2.x** series offered multiple modes (AES-GCM, ChaCha20-Poly1305, AES-CTR+HMAC) and a footer `END0/NAM0`. **3.0** simplifies to a single cryptographic path (SecretStream) and integrates the footer as authenticated `TAG_FINAL`, preserving the same benefits of integrity, truncation-proofing, and extension restoration.

---

## 🔧 How it works (v3.0 format overview)

* **Header** (written by libsodium SecretStream) + **KDF header** are **AAD**. Any alteration => authentication failure.
* **Frames**: the plaintext is processed in chunks; each output of `push()` is authenticated.
* **Final tag**: a `TAG_FINAL` closes the stream and carries **authenticated metadata** (`orig_name`, `orig_ext`, `pt_size`, etc.).
* **Size privacy**: optionally, the last block receives **padding** (0 / 4 / 8 / **16 KiB**). The real plaintext size is verified from `pt_size` in `TAG_FINAL`.

---

## 🧪 Security model (quick notes)

* **XChaCha20-Poly1305** (AEAD) provides confidentiality + per-frame integrity; `TAG_FINAL` authenticates stream closure.
* **Argon2id** hardens each password guess (Sensitive > Interactive). A strong passphrase remains the primary factor.
* **Header AAD** prevents downgrade/parameter tampering and provides a **commitment** between header and payload.
* **Vault** stores **only already-encrypted outputs**; it adds an optional layer of protection and organization.

---

## 📦 Installation

### A) Windows executable (end-users)

1. Download the `.exe` from **Releases**.
2. Run it normally.

   > Tip: do not run as Administrator — UAC blocks drag-and-drop from non-elevated windows.

### B) From source (Python 3.11+)

```bash
git clone https://github.com/<your-user>/CryptGuardv2.git
cd CryptGuardv2
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate
pip install -r requirements.txt
python main_app.py
```

### C) Slim build (PyInstaller, Windows)

```powershell
pyinstaller --onefile --windowed --name "CryptGuard" --icon .\cryptguard.ico main_app.py
```

> Avoid `--collect-all`. Add only the necessary Qt plugins via `--collect-data/--collect-binaries`/`--hidden-import`. Make sure **PyNaCl/libsodium** are present for SecretStream.

---

## 🖥️ Using the app

1. Select (or drag) a file.
2. Choose **KDF profile** (Interactive/Sensitive) and, if you want, **Pad size** (0–16 KiB).
3. (Optional) **Expiration date**.
4. Enter a **strong passphrase** and click **Encrypt**.
5. To **Decrypt**, select the `.cg2` and click **Decrypt**.

   * The file is saved with its original name/ext. If a conflict exists, `name(1).ext` is created.
6. **Verify** checks integrity without writing output to disk.
7. **Vault**: tick **Store encrypted file in Vault** when encrypting to move it to the Vault; use the **Vault** button to list/export.
8. **KeyGuard**: use the integrated password generator in the side panel to create secure passwords with customizable length and character sets. Generated passwords can be stored in the KeyGuard vault for later retrieval.

---

## 🔑 KeyGuard Password Generator

CryptGuard v3.0 includes **KeyGuard**, an integrated secure password generator that appears as a sidebar in the main interface. This feature provides:

### Core Features

* **Cryptographically secure generation**: Uses Python's `secrets` module for strong randomness
* **Entropy calculation**: Real-time entropy estimation to ensure password strength
* **Multiple character sets**:
  * **Numbers**: 0-9 (10 characters)
  * **Letters**: a-z, A-Z (52 characters)  
  * **Alphanumeric**: Letters + Numbers (62 characters)
  * **Full**: Letters + Numbers + Punctuation (94 characters)
* **Customizable length**: Generate passwords from 1 to 128+ characters
* **Pattern rejection**: Automatically rejects weak patterns during generation

### KeyGuard Vault

* **Secure storage**: Dedicated vault for storing generated passwords and entries
* **Atomic operations**: Safe file operations with automatic backup recovery
* **Compression**: Transparent gzip compression before encryption
* **Rate limiting**: Built-in protection against brute-force attempts
* **Entry management**: Add, edit, delete, and reorder password entries

### Integration

* **Non-intrusive UI**: Appears as a collapsible sidebar panel
* **Qt and Tk support**: Works with both PySide6 and tkinter interfaces
* **Dynamic loading**: Graceful fallback if KeyGuard modules are unavailable
* **Vault synchronization**: Can integrate with the main CryptGuard vault system

### Usage Tips

* Use **Full** character set for maximum security when possible
* Aim for passwords with **50+ bits** of entropy (shown in real-time)
* Store frequently used passwords in the KeyGuard vault for convenience
* Use longer passwords (12+ characters) rather than shorter complex ones

---

## ⚙️ Tuning & options

* **KDF profile**

  * **Interactive**: everyday use; lower latency and RAM.
  * **Sensitive**: higher cost per guess (more time/RAM).
* **Pad size**: **0 / 4 / 8 / 16 KiB**.

  * Larger pad ⇒ better size camouflage, larger `.cg2`.
  * For strong type/size camouflage, combine with **ZIP/Archive** before encrypting.
* **Expiration**: non-secret metadata; apps can use it as a signal (does not prevent decryption).

---

## 🔍 Troubleshooting

* "InvalidTag / authentication failed": corrupted file (header, frame, or final).
* No extension after decrypt: in 3.0 this is restored automatically; if you choose an `out_path` with a different extension, it will be honored.
* Drag-and-drop doesn't work: do not run as Admin (UAC).
* Huge PyInstaller build: avoid `--collect-all`; make a slim build.
* KeyGuard sidebar not appearing: check that the KeyGuard modules are present in `modules/keyguard/`. The app will show a status message if import fails.
* KeyGuard vault locked/corrupted: use the vault recovery options or recreate the KeyGuard vault if needed.

---

## 🧠 Tips

* Prefer **long passphrases** (4–6 random words) and unique ones.
* **Sensitive** is more resistant to brute-force; use it when you can tolerate higher latency.
* Do not decrypt sensitive content on possibly compromised machines.
* **Backups**: if you lose both the Vault and the passphrase, the content is unrecoverable.
* **KeyGuard passwords**: use the integrated generator for creating strong passphrases for your encrypted files.
* **Multiple vaults**: KeyGuard vault and main CryptGuard vault are separate - back up both if you use them.

---

## 🤝 Contributing

PRs welcome (include reproduction steps and tests).
For security issues, do not open a public issue — use **SECURITY.md**.

---

## 📜 License

Apache License 2.0 — see [`LICENSE`](./LICENSE).

---

## 🛡️ Security Policy

See [`SECURITY.md`](./SECURITY.md).

---

## 📚 Changelog (summary)

* **3.0**

  * **New**: single writer **XChaCha20-Poly1305 SecretStream**; header as **AAD**; `TAG_FINAL` with authenticated metadata; automatic name/ext restoration; **Pad size ceiling = 16 KiB**; KDF profiles **Interactive/Sensitive**; Vault with AAD + `SecureFormatter`.
  * **Compat**: reading old formats (v1–v4). Writing always in the new format.
  
* **2.7.0**

  * Multi-algorithm (AES-GCM / ChaCha20-Poly1305 / AES-CTR+HMAC), authenticated header/footer (`END0/NAM0`), initial Vault, padding up to **1 MiB**, etc.

---

## 🌍 Export Compliance (US EAR) — **Binary Releases**

This repository contains **publicly available encryption source code** implementing standardized algorithms (AES-GCM, ChaCha20-Poly1305, XChaCha20, etc.).
Under the U.S. Export Administration Regulations (EAR), publicly available encryption **source code** is generally **not subject** to the EAR once published (see 15 CFR 742.15(b)).

When we distribute **binaries** (e.g., Windows `.exe`) via Releases, they are **classified under ECCN 5D002** and are made available under **License Exception ENC**.

**By downloading binaries, you agree to comply with applicable export/sanctions laws.**
Do not export or re-export to sanctioned jurisdictions/users.

---

## 🙏 Acknowledgements / Third-party

* `cryptography` (Apache-2.0)
* `argon2-cffi` (MIT)
* `reedsolo` (MIT)
* `PySide6 / Qt` (LGPL-3.0; additional Qt terms may apply)
* `zxcvbn-python` (MIT)
* `PyNaCl` (ISC) — optional fallback for XChaCha20-Poly1305
