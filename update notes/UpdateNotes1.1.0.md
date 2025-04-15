# 📜 CryptGuard Update Notes

**Version:** 1.1.0  
**Date:** April 2025  

---

## 🚀 Summary of Changes

This release brings even deeper improvements to how CryptGuard manages **memory** and **diversifies** its encryption approaches, with the goal of minimizing the exposure of keys and passwords in RAM.  
The update also reorganizes the project into modules, separating cryptographic logic ("core") from business logic and user interface.

---

## 🗃️ Project Structure & Module Segregation

- **New `crypto_core/` package:**  
  - Contains all essential cryptographic components (key derivation, obfuscation, streaming, single-shot, metadata handling, etc.).  
  - Facilitates security audits and maintenance, as sensitive code is no longer mixed with application logic.

- **UI & Business Logic in Root Directory:**  
  - Files like `main.py`, `hidden_volume.py`, `password_utils.py`, and `file_chooser.py` now handle user interaction, prompts, file selection, etc.  
  - These scripts now import cryptographic methods from `crypto_core.*`.

### Why is this important?

Segregating cryptographic logic allows for better **organization**, **reusability** (e.g., using these functions in other projects), and **easier security auditing**. It also makes the project more sustainable as it grows.

---

## 🔒 Re-Obfuscation and Single-Shot Logic Enhancements

### ➤ **Re-Obfuscation for “Medium-Sized” Files**  
- Previously, the *single-shot* mode would encrypt the entire file in one go, keeping the deobfuscated key in memory throughout the process.  
- Now, if the file isn’t large enough to trigger *streaming*, but exceeds a configurable limit (`SINGLE_SHOT_SUBCHUNK_SIZE`), the **content is encrypted in sub-blocks** in memory.  
- For each sub-block, the key is **deobfuscated**, used, and then **re-obfuscated**, reducing the time the key is exposed in RAM.

### ➤ **Compatibility and Metadata**  
- A new `multi_sub_block` field has been added to the `metadata` of single-shot files that use sub-blocks.  
- **`decrypt_data_single`** detects this field and decrypts in multiple blocks (similar to streaming), re-obfuscating the key for each chunk.

### ➤ **Practical Effect**  
- Keys remain in plaintext memory for even less time, even with moderately sized files.  
- For very large files, **streaming mode** is still preferred (with disk chunk re-obfuscation).  
- For small files, single-block processing remains since the operation is fast enough.

---

## 🧩 Secure Memory & Password Handling

The changes introduced in version 1.0.1 remain and have been **consolidated** in this release, including:

- **`SecureBytes`** to store passwords and keys in mutable `bytearray` structures.  
- **`KeyObfuscator`** to mask derived keys, exposing them only briefly during encryption/decryption.  
- **Explicit clearing** (zeroization) of memory buffers in `finally` blocks to ensure passwords aren’t left in memory due to crashes or exceptions.  
- **Argon2 support** with parameter fallback in case of `MemoryError`.

---

## 🗂️ Other Improvements

- **Dually encrypted metadata** (decoy + real) for hidden volumes.  
- **Configurable Reed-Solomon** (`RS_PARITY_BYTES`) and refactored `rs_codec.py`.  
- **`SIGN_METADATA` option** to digitally sign encrypted files using an HMAC with the derived key (to prevent silent tampering).

---

## ⚙️ Relevant Configuration Settings

Inside `crypto_core/config.py`:

- `SINGLE_SHOT_SUBCHUNK_SIZE`: defines the sub-block size for single-shot mode with re-obfuscation.  
- `STREAMING_THRESHOLD`: above this value, encryption automatically switches to streaming mode.  
- `CHUNK_SIZE`: chunk size for streaming mode.  
- `MAX_CHUNK_SIZE`: chunk/subchunk memory usage limiter.

---

## 🛡️ Security and Impact

| Aspect                        | Previous Version     | New Version 1.1.0                        |
|------------------------------|----------------------|------------------------------------------|
| Project Structure            | Mixed code           | Segregated modules in `crypto_core/`     |
| Re-Obfuscation in single-shot| Not applied          | Sub-blocks in memory (partial "streaming")|
| Key Exposure Time            | Higher               | Reduced (more frequent re-obfuscation)   |
| Overall Security             | Good                 | Improved (less RAM exposure)             |
| Code Auditing                | More difficult        | Easier with modular structure            |

---

## 📈 Migration and Compatibility

- **Older single-shot files** remain fully compatible, as they don’t contain the `multi_sub_block = True` flag, and are processed as before.  
- **New single-shot files** (using sub-blocks) still use the `.enc` extension, but `decrypt_data_single` detects `multi_sub_block = True` and decrypts accordingly.  
- **Hidden Volumes** remain unchanged in main workflow, aside from overall security gains.

---

## 🏁 Conclusion

This version 1.1.0 reinforces CryptGuard’s core philosophy of **minimizing key exposure** during encryption and decryption, further enhancing resistance to attacks involving memory inspection (RAM forensics, cold boot attacks, etc.).  
The new project layout, with a fully isolated cryptographic layer, adheres to software engineering best practices and enables easier auditing, maintenance, and future expansions.

**We strongly recommend upgrading** to version 1.1.0 or later to take advantage of these security and organizational benefits.
