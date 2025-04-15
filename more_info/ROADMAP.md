# CryptGuard Roadmap

This document outlines CryptGuard’s **current features** and **future plans**, reflecting updates introduced in the **v1.1.0** release.

---

## ✨ Overview of Current Features

| Option | Functionality                                                       |
|--------|---------------------------------------------------------------------|
| 1️⃣     | **Encrypt Text**                                                   |
| 2️⃣     | **Open File Selection Window**                                     |
| 3️⃣     | **Decrypt File**                                                  |
| 4️⃣     | **Encrypt Multiple Files**                                         |
| 5️⃣     | **Generate Ephemeral Token**                                       |
| 6️⃣     | **Create Hidden Volume (Plausible Deniability)**                  |
| 7️⃣     | **Key Rolling (Normal Volume)**                                    |
| 8️⃣     | **Change Password of Real Volume (Hidden)**                        |
| 0️⃣     | **Exit**                                                           |

### Core Technologies and Updates

- **ChaCha20-Poly1305** for robust authenticated encryption.
- **Argon2id** with fallback if `MemoryError` occurs (auto-reduces `memory_cost`).
- **Reed-Solomon** for optional error correction and minor corruption recovery.
- **Streaming Mode** for large files, reducing RAM usage by encrypting/decrypting in chunks.
- **Single-Shot Mode** now supports **sub-chunk encryption** with **re-obfuscation** for medium-sized files.
- **Double-layer Metadata Encryption** to protect file parameters and hidden-volume info.
- **Sensitive Data Cleanup**: zeroizes passwords, tokens, and derived keys after usage.

---

## 🔒 Detailed Functionality

### 1️⃣ Encrypt Text
- **User Input**: Paste or type your message, then provide a password (with confirmation).
- **Encryption**: Uses single-shot encryption (via `encrypt_data_single`).
- **Metadata**: Stores the Argon2 parameters, timestamps, and original extension (`.txt`) securely in `.meta`.

### 2️⃣ Open File Selection Window
- **GUI**: Select files from a graphical dialog.
- **Threshold Check**: If the file(s) exceed `STREAMING_THRESHOLD`, streaming mode is used automatically.
- **Outcome**: An `.enc` file plus a `.meta` file containing securely encrypted metadata.

### 3️⃣ Decrypt File
- **Input**: Pick the `.enc` file, enter your password (and key file if applicable).
- **Hidden/Normal Detection**: If it’s from a hidden volume, ephemeral token might be required. Otherwise, normal decryption proceeds.
- **Result**: Decrypted file recovers its original extension.

### 4️⃣ Encrypt Multiple Files
1. User selects multiple files.
2. The files are zipped together.
3. If the resulting ZIP is large, streaming is used; otherwise, single-shot mode is applied.
4. Result: A single `.enc` plus `.meta`, containing compressed content of all selected files.

### 5️⃣ Generate Ephemeral Token
- **Purpose**: Additional secret for hidden volumes.
- **High Entropy**: A hex token is generated; losing it makes real volume data inaccessible, even with the correct password.

### 6️⃣ Create Hidden Volume
1. Select a decoy file (fake data) and a real file (sensitive data).
2. Provide separate passwords for decoy and real volume, plus an ephemeral token for real volume access.
3. Outputs `.enc`, `.meta` (for decoy) and `.meta_hidden` (for the real volume), along with random padding and optional Reed-Solomon encoding.

### 7️⃣ Key Rolling (Normal Volume)
- **Objective**: Change a normal volume’s password without exposing data unprotected on disk.
1. Decrypt with the old password.
2. Re-encrypt with a new password.
3. Optionally remove the old `.enc` to finalize the key change.

### 8️⃣ Change Password of Real Volume (Hidden)
1. Authenticate decoy volume (outer metadata).
2. Provide the real password + ephemeral token to decrypt the real data in memory.
3. Re-encrypt it under a new password, updating `.meta_hidden`.

### 0️⃣ Exit
- Closes the CryptGuard session safely.

---

## 🛠 Maintenance and Versions

- **Current Version**: **v1.1.0**  
  - **Sub-Chunk Re-Obfuscation** for single-shot mode, minimizing key exposure in medium-sized files.  
  - **Project Structure Segregation**: cryptographic logic centralized in `crypto_core/`.  
  - **Metadata**: double-layer encryption, with optional signature (HMAC) for tamper detection.  
  - **Zeroization**: Enhanced memory cleanup for derived keys, ephemeral tokens, and passwords.

- **Backward Compatibility**:  
  - Pre-v1.0 `.enc` files (with old plaintext checksums) remain **incompatible** with the newer format.  
  - Single-shot files that use multi-sub-block encryption store `multi_sub_block = true` in `.meta`, requiring v1.1.0 or above to decrypt them properly.

---

## 🤝 Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get involved:
- Propose features or report bugs via **Issues**.
- Fork and submit **Pull Requests** for code changes.
- For security disclosures, please check [SECURITY.md](../SECURITY.md).

---

**Last Updated**: April 2025  
© CryptGuard Team - Elevate your security!  
