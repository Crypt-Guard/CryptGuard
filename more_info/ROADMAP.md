# CryptGuard Roadmap

This document outlines CryptGuard’s **current features** and **future plans**, reflecting updates introduced in the latest version.

---

## ✨ Overview of Current Features

| Option | Functionality                                                   |
|--------|-----------------------------------------------------------------|
| 1️⃣     | **Encrypt Text**                                               |
| 2️⃣     | **Open File Selection Window**                                 |
| 3️⃣     | **Decrypt File**                                              |
| 4️⃣     | **Encrypt Multiple Files**                                     |
| 5️⃣     | **Generate Ephemeral Token**                                   |
| 6️⃣     | **Create Hidden Volume (Plausible Deniability)**              |
| 7️⃣     | **Key Rolling (Normal Volume)**                                |
| 8️⃣     | **Change Password of Real Volume (Hidden)**                    |
| 0️⃣     | **Exit**                                                       |

### Core Technologies and Updates

- **ChaCha20-Poly1305** for robust authenticated encryption.
- **Argon2id** with fallback if `MemoryError` occurs (auto-reduces `memory_cost`).
- **Reed-Solomon** for optional error correction.
- **Streaming Mode** for efficient encryption/decryption of large files.
- **Atomic Metadata Writes** to prevent corruption if interrupted.
- **Sensitive Data Cleanup**: zeroizes critical buffers (e.g., derived keys, passwords).

---

## 🔒 Detailed Functionality

### 1️⃣ Encrypt Text
- **User Input**: Paste or type your message, then provide a password (with confirmation).
- **Encryption**: Uses single-shot encryption (via `encrypt_data_single`).
- **Metadata**: Original extension (`.txt`), Argon2 parameters, and timestamps stored securely in `.meta`.

### 2️⃣ Open File Selection Window
- **Graphical Selection**: Pick one or more files from any folder.
- **Threshold Check**: Files above a configurable size (e.g., 10MB) switch to streaming mode to prevent high RAM usage.
- **Outcome**: Encrypted file (`.enc`) plus a `.meta` file containing safely encrypted metadata.

### 3️⃣ Decrypt File
- **Select and Confirm**: Choose the `.enc` file, provide the correct password and optional key file if used during encryption.
- **Hidden or Normal**: If the file is part of a hidden volume, an ephemeral token may be required; otherwise, normal decryption proceeds.
- **Restoration**: Decrypted file recovers its original extension.

### 4️⃣ Encrypt Multiple Files
- **Flow**:
  1. User selects multiple files.
  2. They are zipped together.
  3. Large ZIPs use streaming; smaller ones use single-shot.
- **Outcome**: A single encrypted `.enc` containing all the selected files compressed in a ZIP, plus corresponding `.meta`.

### 5️⃣ Generate Ephemeral Token
- **Ephemeral Token**: Creates a random token (hex) with high entropy.
- **Real Volume Access**: Required for hidden volumes. Keep it safe—losing it makes the real volume inaccessible, even if you know the password.

### 6️⃣ Create Hidden Volume (Plausible Deniability)
- **Setup**:
  1. Decoy file (fake data).
  2. Real file (sensitive data).
  3. Two distinct passwords + ephemeral token for the real file.
- **Concatenation**: Decoy and real ciphertext are combined with padding and optionally protected by Reed-Solomon.
- **Dual Metadata**: `.meta` for decoy info, `.meta_hidden` for real volume.

### 7️⃣ Key Rolling (Normal Volume)
- **Intent**: Safely replace the encryption key with a new password.
- **Process**:
  1. Decrypt with old password (and key file if applicable).
  2. Re-encrypt the data with a new password.
  3. Optionally remove the old `.enc` to invalidate the old key.

### 8️⃣ Change Password of Real Volume (Hidden)
- **Dual Authentication**:
  1. Decoy password → Access outer metadata.
  2. Real password + ephemeral token → Access the real content.
- **Process**:
  1. Temporarily decrypt the real part in memory.
  2. Re-encrypt it with the new password/parameters.
  3. Update `.meta_hidden` without exposing the decoy.

### 0️⃣ Exit
- Closes the CryptGuard session.

---

## 🛠 Maintenance and Versions

- **Current Version**: *v1.0 (Major Update)*  
  - Removed plaintext checksums  
  - Improved Argon2 fallback  
  - Atomic .meta writes  
  - Enhanced streaming + error handling  
  - Memory zeroization for derived keys/passwords

- **Backward Compatibility**: Old `.enc` files with the old plaintext-checksum format are **not** compatible unless an older version is used. It’s recommended to decrypt and re-encrypt with the updated version if needed.

---

## 🤝 Contribute

We appreciate community involvement. See our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. For any security concerns, please refer to [SECURITY.md](../SECURITY.md).

---

**Last Updated**: *Month YYYY*  
&copy; CryptGuard Team - Secure your data!
