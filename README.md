````markdown
# 🔐 CryptGuard v2 — Version 2.7.0 (August 2025)

**CryptGuard v2** is a modern file-encryption app with a Qt (PySide6) GUI and a security-first format (**CG2**).  
It features per-chunk AEAD encryption, strong Argon2id KDF, an **authenticated header**, **anti-truncation footer**, optional **size padding**, a **ciphered original extension** that’s restored on decrypt — even if you rename the `.cg2` — **and a built-in Vault** to safely keep your encrypted files.

---

## ✨ Highlights

| #  | Feature                                   | What it does                                                                                                                                   |
|----|-------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  | **Chunked AEAD**                          | AES-256-GCM, ChaCha20-Poly1305, **XChaCha20-Poly1305** (24-byte nonce). **Unique nonce per chunk** (random base + counter derivation).         |
| 2  | **Authenticated header (AAD)**            | Algorithm, nonce/IV, Argon2id params, and expiration live in an **authenticated** header (AAD). Prevents parameter tampering/downgrade.        |
| 3  | **Anti-truncation footer (AEAD)**         | Requires a final **`END0`** record that authenticates `(chunk_count, total_plain_len)` via HKDF-derived key. Cut on chunk boundary → **fail**. |
| 4  | **AES-CTR + HMAC**                        | CTR mode uses **HMAC-SHA256** (keys split via HKDF) and a **`SIZ0`** record (true plaintext size). Robust encrypt-then-MAC design.             |
| 5  | **Ciphered original extension (`NAM0`)**  | The original extension is written **encrypted** in the footer. Decrypt restores `.py`, `.torrent`, `.csv`, etc., with no type leak in header. |
| 6  | **Size padding (per chunk)**              | “Pad size” (Off / 4 KiB / 16 KiB / 64 KiB / 1 MiB). Hides exact size on the wire; decrypt **truncates** to the true size from the footer.     |
| 7  | **Argon2id KDF**                          | Auto-calibration; profiles **Fast / Balanced / Hard**. Fresh random salt per file.                                                             |
| 8  | **Polished GUI**                          | Drag-and-drop, password strength (optional), Cancel, working **Log** button, **Pad size** selector, optional expiration.                       |
| 9  | **Thread-safe rate-limit**                | Shared counters protected with a lock; reset on success.                                                                                       |
| 10 | **Process hardening (best-effort)**       | `mlock/VirtualLock` attempts, secure logging, careful memory handling.                                                                         |
| 11 | **Built-in Vault**                        | Local, passphrase-protected **Vault** to store your **already-encrypted** `.cg2` files — simple, private, and convenient.                      |

---

## 🆕 What’s new in **2.7.0**

- **CG2 v4**: authenticated header **without** exposing the original extension (privacy). Reads older **v3** files as well (legacy extension still honored if present).
- **`END0` footer (AEAD)**: detects truncation even when the cut happens exactly at a chunk boundary (this used to pass unnoticed).
- **`NAM0` (ciphered extension)**: decrypt restores the original extension even if the `.cg2` was renamed (no leak in header or filename).
- **Per-chunk padding + truncate**: configurable **Pad size**; decrypt truncates to the true plaintext length stored in the footer.
- **GUI**: “Pad size” selector; **Log** button reliably opens the log; XChaCha shows up if either **cryptography** or **PyNaCl** backends are present; drag-and-drop tip when elevated (UAC).
- **Packaging**: slim PyInstaller guidance (avoid `--collect-all`), plus option to exclude PyNaCl when not needed.
- **New: Vault** — a passphrase-protected local store that keeps your encrypted outputs in one place and hides them from casual browsing.

> **Compatibility**: New files are **v4** (with `END0` + `NAM0`). Old **v3** files still decrypt. For very old CTR files without HMAC, re-encrypt to gain full integrity.

---

## 🏦 The Vault (what it is and how it works)

**What it is**  
The Vault is an **optional** local repository to store your **encrypted outputs** (`.cg2`). It is **not** a cloud; it lives on your machine and is protected by its **own passphrase**.

**Function & workflow**
- When you encrypt a file, tick **“Store encrypted file in Vault”**. The resulting `.cg2` is moved **into** the Vault.
- Open the Vault from the status bar (**Vault** button) to **list** or **export** items when you need them.
- Exporting restores the `.cg2` to a location you choose (you can then decrypt as usual).

**Security model**
- The Vault **never stores plaintext**. Items inside it are your **already-encrypted** `.cg2` files — so they’re **double-wrapped**: CG2 crypto **inside**, Vault crypto **outside**.
- Vault encryption uses strong primitives (AEAD ChaCha20-Poly1305/XChaCha20-Poly1305 where available) and keys derived with **Argon2id** calibrated for your system.  
- The Vault file includes **integrity checks**, serialized atomically (WAL/backup strategy) and with restricted file permissions where the OS allows.
- In-memory secrets are handled carefully (short-lived exposure, masking/rotation, best-effort page locking).

**How useful is it?**
- **Convenience**: one place to keep your encrypted artifacts — no scattered `.cg2` files.  
- **Privacy**: avoids leaving obvious `.cg2` files around; keeps them out of casual Explorer/Finder searches.  
- **Defense-in-depth**: if someone grabs your Vault file, they must first break the **Vault** and then the **CG2** layer.

> The Vault improves practical security and hygiene. It does **not** defend against a fully compromised machine (malware/root), and it’s only as strong as its passphrase and your OS protection.

---

## 📦 Supported Algorithms

- **AES-256-GCM** (AEAD)  
- **XChaCha20-Poly1305** (AEAD, 24-byte nonce; via `cryptography` or fallback PyNaCl/libsodium)  
- **ChaCha20-Poly1305** (AEAD)  
- **AES-256-CTR + HMAC-SHA256** (encrypt-then-MAC, with `SIZ0` true size record)

---

## 🗃️ CG2 File Format (v4) — overview

- **Header (AAD)**:  
  `MAGIC | VERSION | ALG | KDF_LEN | KDF_JSON | NONCE_LEN | NONCE | EXP_TS`  
  *Authenticated as AAD by AEAD modes; tampering triggers failure.*

- **Payload framing (all modes)**:  
  Repeated `4-byte big-endian length || ciphertext_chunk`.

- **Footer**:
  - **AEAD**:  
    `NAM0` *(encrypted original extension)* → `END0 | 4B length | AESGCM(final_key).encrypt(nonce=0, payload=(chunks, total_pt), aad=header)`  
    Detects truncation and carries the **true plaintext length** (`total_pt`).
  - **CTR**:  
    `NAM0` *(included in HMAC)* → `[SIZ0 | 8B total_pt]` → `TAG0 | 32B HMAC`  
    HMAC covers: header AAD, every `len||ct` pair, `NAM0` (if present), and `SIZ0`.

- **Privacy**:
  - The **original extension is not in the header** (unlike v3).  
  - The extension is stored **encrypted** in `NAM0` and restored on decrypt — even if the user renames the `.cg2`.

---

## 🔑 KDF & Header Parameters

- **Argon2id** with per-file **random salt** (public, by design).  
- `time_cost`, `memory_cost`, `parallelism` are **not secrets**; they are authenticated and prevent downgrade attacks.  
- Use strong passphrases; KDF parameters are calibrated automatically and can be tuned via profiles.

---

## 🚀 Getting Started

### A) Windows executable (recommended for end-users)
1. Download the `.exe` from **Releases**.  
2. Run it normally.  
   > **Tip:** don’t “Run as administrator” — Windows blocks drag-and-drop into elevated apps (UAC).

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
````

### C) Build a **slim** Windows executable (PyInstaller)

```powershell
# Slim build (~50–70 MB). Excludes PyNaCl fallback for XChaCha.
pyinstaller --onefile --windowed --name "CryptGuardv2" --icon .\cryptguard.ico --exclude-module nacl main_app.py

# Need XChaCha fallback via PyNaCl/libsodium? Remove the exclude:
# pyinstaller --onefile --windowed --name "CryptGuardv2" --icon .\cryptguard.ico main_app.py
```

> Avoid `--collect-all` (bloats to >200 MB). If Qt complains about missing plugins, add **only** what’s needed via `--collect-data/--collect-binaries` or `--hidden-import`.

---

## 🖥️ Using the App (GUI)

1. **Open** the app, **drag & drop** a file (or click **Select…**).
2. Choose **Algorithm** and **Security profile**.
3. (Optional) Set **Pad size**: Off / 4 KiB / 16 KiB / 64 KiB / 1 MiB.

   * Larger padding ⇒ better size obfuscation, larger `.cg2`.
   * Decrypt restores the exact file (truncate per footer).
4. (Optional) Set an **Expiration** date.
5. Enter a **strong passphrase** and click **Encrypt**.
6. To decrypt, drop or select a `.cg2` and click **Decrypt**.

   * The original extension is restored via `NAM0` (even if the `.cg2` was renamed).
7. **Vault usage**:

   * During **Encrypt**, tick **“Store encrypted file in Vault”** to move the output into the Vault automatically.
   * Click **Vault** in the status bar to open the Vault dialog: **list** items and **export** selected entries to a folder of your choice.
   * The Vault holds **only encrypted `.cg2` files**; exporting does not decrypt — you can decrypt exported items as usual.

---

## 🔍 Integrity & Truncation Protection

* **AEAD**: Decrypt fails if the **`END0`** footer is missing/tampered (detects truncation including “on chunk boundary”).
* **CTR**: Decrypt fails if **HMAC** doesn’t match; **`SIZ0`** carries the true plaintext size; any padding is removed by truncation.

---

## 🧠 Security Tips

* Use **long passphrases** (12+ chars or 4–6 random words).
* **Balanced** profile is a good default; increase to **Hard** if your machine has plenty of RAM.
* Default **Pad size**: 4 KiB (good trade-off). Bump to 16–64 KiB if size correlation matters; turn **Off** for smallest `.cg2`.
* Don’t decrypt sensitive files on compromised systems.
* `mlock/VirtualLock` is **best-effort**; it reduces risk of paging sensitive data but is not a silver bullet.
* **Vault**: choose a **strong, unique passphrase**; keep backups of the Vault file if losing it would be critical.

---

## ⚠️ Known Limitations

* Malware or OS-level compromise can capture passwords or plaintext.
* Size padding masks exact size but not high-level traffic analysis.
* File metadata (names, timestamps, paths) outside the `.cg2` remain visible to the OS/filesystem.
* The Vault improves privacy and convenience but is only as strong as its passphrase and your OS protections.

---

## 🐞 Troubleshooting

* **Drag & drop doesn’t work on Windows** → Don’t run the app as Administrator (UAC prevents dropping from non-elevated Explorer).
* **XChaCha missing in algorithm list** → Ensure `cryptography` is recent; or install `PyNaCl` to enable fallback.
* **PyInstaller build is huge** → Avoid `--collect-all`; use the **slim** command above.
* **“Footer missing/truncated”** on decrypt → The file is corrupted or incomplete (protection working as intended).
* **Vault export/decrypt confusion** → Exporting from the Vault yields the `.cg2` file; decrypt it as usual in the main window.

---

## 🤝 Contributing

PRs are welcome! Please include clear reproduction steps and tests where applicable.
For security issues, **do not** open a public issue — see **SECURITY.md**.

---

## 📜 License

Licensed under **Apache License 2.0**.
See [`LICENSE.txt`](./LICENSE.txt) for details.

---

## 🛡️ Security Policy

See [`SECURITY.md`](./SECURITY.md).

---

## 🌍 Export Compliance (US EAR) — **Binary Releases**

This repository contains **publicly available encryption source code** implementing standardized algorithms (AES-GCM, ChaCha20-Poly1305, XChaCha20, etc.).
Under the U.S. Export Administration Regulations (EAR), publicly available encryption **source code** is generally **not subject** to the EAR once published (see 15 CFR 742.15(b)).

When we distribute **binaries** (e.g., Windows `.exe`) via Releases, they are **classified under ECCN 5D002** and are made available under **License Exception ENC**.

**By downloading binaries, you agree to comply with applicable export/sanctions laws.**
Do not export or re-export to sanctioned jurisdictions/users.
*(This is not legal advice.)*

---

## 🙏 Acknowledgements / Third-party

* `cryptography` (Apache-2.0)
* `argon2-cffi` (MIT)
* `reedsolo` (MIT)
* `PySide6 / Qt` (LGPL-3.0; additional Qt terms may apply)
* `zxcvbn-python` (MIT)
* `PyNaCl` (ISC) — optional fallback for XChaCha20-Poly1305

```
