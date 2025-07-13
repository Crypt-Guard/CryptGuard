# CryptGuard v2 Roadmap

**Current Version:** v2.5 (July 2025)

---

## 🏁 1. Current Features

### Core Encryption
- **AES-256-GCM** (streaming) & **ChaCha20-Poly1305** (single-shot & streaming)  
- **Argon2id**-based KDF (Fast, Balanced, Secure profiles) with auto-calibration  
- **HKDF-SHA256** sub-key separation: `enc_key` + `hmac_key`  

### Integrity & Redundancy
- **HMAC-SHA256** global authentication tag  
- **Reed–Solomon** per-chunk optional error-correction (32 bytes parity)  
- **Metadata encryption** with ChaCha20-Poly1305 (salt + nonce + ciphertext)  

### Memory & Process Hardening
- **SecureBytes** (mlock/VirtualLock + multi-pass zeroization)  
- **KeyObfuscator** (XOR mask + timed exposure)  
- Optional `--harden` flag: DEP, error-mode, anti-debug checks  

### Usability / UX
- **PySide6 GUI**: drag-&-drop, file picker, confirm-password, strength meter, progress bar  
- **Secure Delete**: overwrite + remove original file  
- **Atomic Writes**: safe rename + chmod(600)  
- **Rotating Log**: SecureFormatter + 1 MB×5 backups  
- **CLI flags**: `--calibrate-kdf`, `--harden`  

### Testing & Packaging
- **pytest** suite: round-trip, bad-password, corrupt data, edge cases  
- **PyInstaller** build: `--onefile --windowed --icon cryptguard.ico`  

---

## 🔜 2. Near-Term Roadmap (v2.x)

1. **Multi-Platform Builds**  
   - Native macOS (`.app`) and Linux (AppImage / DEB)  
2. **Hidden Volumes** & Plausible Deniability  
3. **Key Rolling** for encrypted archives  
4. **Exportable Checksums** & Verification Mode  
5. **FIPS-compliant Mode** & PKCS#11 Token Support  

---

## 🚀 3. Long-Term Goals (v3.0+)

- **Automated Updater** with signed releases  
- **Plugin API** for custom algorithms  

---

_Last updated: July 2025_  
