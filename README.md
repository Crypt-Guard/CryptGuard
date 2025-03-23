# 🔐 CryptGuard

<div align="center">

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-audited-green.svg)](SECURITY.md)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](CONTRIBUTING.md)

**CryptGuard is an advanced encryption solution with a modern interface, focused on security and usability.**

[💡 Usage Guide](#-usage-guide) •
[📖 Documentation](#-documentation) •
[🛡️ Security](#️-security) •
[🤝 Contribute](#-contribute) •
[📜 License](#-license)

</div>

CryptGuard is an advanced encryption solution with a focus on security and usability, now restructured into a modular architecture.

--------------------------------------------------------------------------------
## ✨ Features

- 🔒 **Robust Encryption**
  • Authenticated encryption with ChaCha20Poly1305
  • Key derivation with Argon2id
  • Error correction with Reed-Solomon

- 🎯 **Advanced Functionalities**
  • Encryption of texts and files (single-shot)
  • Large file encryption with streaming mode and dynamic chunk sizes
  • Multiple file support (ZIP compression)
  • Creation of hidden volumes with plausible deniability
  • Key Rolling / Re-encryption: Change the password of the real volume without exposing the hidden one

- Authentication

  • [1] Password + Key-file

  • [2] Password only

- 💫 **CLI Interface**
  • Intuitive command-line interface
  • Real-time feedback during streaming operations

- 🛡️ **Enhanced Security**
  • Password strength verification with zxcvbn
  • Encrypted metadata (including original file extensions)
  • Careful management of sensitive memory (buffer zeroization)

--------------------------------------------------------------------------------

## Project Structure

**The repository is now organized modularly within the "cryptguard/" directory:**

cryptguard/

├── __init__.py             -> Initializes the package

├── config.py               -> Global settings (chunk size, thresholds, Argon2 parameters, etc.)

├── password_utils.py       -> Functions for password validation and collection (Password + Key-file or Password only)

├── argon_utils.py          -> Key derivation with Argon2id

├── metadata.py             -> Metadata encryption and decryption (.meta)

├── rs_codec.py             -> Reed-Solomon encoding and decoding

├── chunk_crypto.py         -> Chunk encryption with ChaCha20Poly1305 + RS

├── single_shot.py          -> Encryption/Decryption for small files (single-shot)

├── streaming.py            -> Encryption/Decryption for large files (streaming, dynamic chunk sizes)

├── hidden_volume.py        -> Hidden volumes functionality and re-keying real volumes

├── utils.py                -> Auxiliary functions (screen clearing, unique name generation, etc.)

└── main.py                 -> Main CLI interface

--------------------------------------------------------------------------------
### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. Clone the repository:
```bash
https://github.com/Crypt-Guard/CryptGuard.git
cd cryptguard
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run CryptGuard:
```bash
python cryptguard/main.py
```
--------------------------------------------------------------------------------
## 💡 Usage Guide

### Encrypting Files
  - Encrypt Text: Enter your message, password (with confirmation), and optionally a key-file.
  - Encrypt File: Choose the file and follow instructions. For large files, you can set a custom chunk size.

### Hidden Volumes
  - Prepare two sets of files: one for the fake volume and one for the real volume.
  - Use distinct passwords for each volume.
  - The system generates an ephemeral token for accessing the real volume.
  - Key Rolling / Re-encryption: Change the password of the real volume without altering or exposing the fake volume.

### Decrypting Files
  - Select the decrypt option and enter the correct password. The file will be restored with its original extension (e.g., .txt, .jpg, etc.).

--------------------------------------------------------------------------------
## 📖 Documentation

- [RoadMap](ROADMAP.md) - Features and future plans
- [Security](SECURITY.md) - Security guidelines and best practices
- [Contributing](CONTRIBUTING.md) - How to contribute to the project
- [License](LICENSE) - Licensing terms

--------------------------------------------------------------------------------
## 🛡️ Security

CryptGuard was designed with security in mind, but we recommend:
  • Authenticated encryption (ChaCha20Poly1305)
  • Key derivation with Argon2id
  • Error correction with Reed-Solomon
  • Password strength validation (zxcvbn)
  • Careful management of sensitive memory (buffer zeroization)

Attention: Conduct security audits and maintain backups of your data.
Refer to [SECURITY.md](SECURITY.md) for more information.

--------------------------------------------------------------------------------
## 🤝 Contribute

Contributions are welcome! Please read our [Contribution Guide](CONTRIBUTING.md).

### Areas of Contribution

- 📝 Documentation
- 🐛 Bug fixes
- ✨ New features
- 🎨 Interface improvements
- 🌐 Translations

## 📜 License

CryptGuard is licensed under the [Apache 2.0 License](LICENSE).

--------------------------------------------------------------------------------

## 📊 Project Status

  - Robust encryption: ✅
  - Complete documentation: ✅
  - Directory support: 🚧
  - Cloud integration: 🚧
  - Physical authentication device support: 🚧

--------------------------------------------------------------------------------

## 🙏 Acknowledgments

We thank the Python community, the developers of the libraries used, and all project contributors.

--------------------------------------------------------------------------------
<div align="center">

**CryptGuard** - Developed with ❤️

[⬆ Back to top](#-cryptguard)

</div>

