# CryptGuard Roadmap

This document outlines CryptGuard’s **current features** and **future plans**, reflecting updates introduced in the **v1.2.0** release.

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
- **Customizable Argon2 Security Profiles** (Fast, Balanced, Secure, Ultra Fast) to manage encryption performance and security.
- **Reed-Solomon** for optional error correction and minor corruption recovery.
- **Streaming Mode** optimized with parallel processing and buffered I/O for enhanced performance on large files.
- **Single-Shot Mode** supports **sub-chunk encryption** with **re-obfuscation** for medium-sized files.
- **Double-layer Metadata Encryption** to protect file parameters and hidden-volume info.
- **Sensitive Data Cleanup**: zeroizes passwords, tokens, and derived keys after usage.

---

## 🔐 Configurable Security Profiles (Argon2 Settings)

Starting from version **1.2.0**, CryptGuard allows users to select different security profiles to balance security and performance:

| Option | Security Profile        | Description                                          |
|--------|-------------------------|------------------------------------------------------|
| **[1]** | **Fast**               | Less secure, faster encryption.                      |
| **[2]** | **Balanced (Default)** | Optimal balance between security and performance.    |
| **[3]** | **Secure**             | Enhanced security, slower performance.               |
| **[4]** | **Ultra Fast**         | Extremely fast, recommended for non-sensitive data.  |
| **[0]** | **Back**               | Return to the previous menu.                         |

These profiles automatically set Argon2 parameters (time, memory, parallelism), allowing users to tailor protection to data sensitivity and available system resources.

---

## 🔒 Detailed Functionality

### 1️⃣ Encrypt Text
- **User Input**: Paste or type your message, then provide a password (with confirmation).
- **Encryption**: Single-shot encryption with secure metadata.

### 2️⃣ Open File Selection Window
- **GUI**: Select files via graphical dialog.
- **Automatic Mode Selection**: Chooses streaming or single-shot based on file size threshold.

### 3️⃣ Decrypt File
- **Input**: Select `.enc` file, provide password (and key file if applicable).
- **Automatic Detection**: Seamlessly handles normal or hidden volume decryption.

### 4️⃣ Encrypt Multiple Files
- Automatically compresses files and selects encryption mode (streaming/single-shot) based on the resulting size.

### 5️⃣ Generate Ephemeral Token
- Generates high-entropy token essential for hidden volume access.

### 6️⃣ Create Hidden Volume
- Securely stores decoy and real data with separate authentication methods (passwords + ephemeral token).

### 7️⃣ Key Rolling (Normal Volume)
- Safely updates encryption password without exposing data in plaintext.

### 8️⃣ Change Password of Real Volume (Hidden)
- Securely changes the password of hidden volume using dual authentication.

### 0️⃣ Exit
- Safely exits the application.

---

## 🛠 Maintenance and Versions

- **Current Version**: **v1.2.0**  
  - **Parallel Processing and Buffered I/O** significantly improve streaming encryption performance.
  - **Dynamic Worker Allocation** optimizes resource usage based on file size.
  - **Argon2 Security Profiles** allow customization of security and performance.
  - Fully translated documentation and comments into English for global accessibility.

- **Backward Compatibility**:  
  - Compatible with `.enc` files created in v1.1.0 and later.
  - Single-shot files using multi-sub-block encryption remain fully supported.

---

## 🤝 Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) to get involved:
- Propose features or report bugs via **Issues**.
- Fork and submit **Pull Requests** for code changes.
- For security disclosures, please check [SECURITY.md](../SECURITY.md).

---

**Last Updated**: April 2025  
© CryptGuard Team - Elevate your security!
