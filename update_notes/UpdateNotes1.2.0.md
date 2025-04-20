# 📜 CryptGuard Update Notes

**Version:** 1.2.0  
**Date:** April 2025  

---

## 🚀 Summary of Changes

Version 1.2.0 brings major performance enhancements and new security profiles to CryptGuard. It optimizes streaming encryption through improved parallel processing and introduces customizable Argon2 security profiles for balancing security and performance.

---

## ⚡ Performance Optimizations

### ➤ **Enhanced Streaming Encryption**
- **Parallel Chunk Processing**: Encryption now uses multithreading via Python's `concurrent.futures` to process chunks in parallel.
- **Dynamic Thread Management**: Introduced the function `calculate_optimal_workers()` to optimize thread count based on file size:
  - Small files (<100 MB): up to 4 threads
  - Medium files (100 MB – 1 GB): up to 8 threads
  - Large files (>1 GB): up to 12 threads
- **Buffered I/O**: File operations use buffered I/O to significantly enhance performance.
- **Progress Feedback**: Added a dynamic progress bar showing percentage completion and encryption speed (MB/s).

---

## 🔒 Argon2 Security Profiles

### ➤ **Configurable Security Settings**
- **Fast Profile**:
  - Lower security, optimized for speed (`time_cost=1`, `memory_cost=64 MB`, `parallelism=4`).
- **Balanced Profile (Default)**:
  - Moderate security, balanced performance (`time_cost=3`, `memory_cost=128 MB`, `parallelism=4`).
- **Secure Profile**:
  - Highest security, slower performance (`time_cost=8`, `memory_cost=256 MB`, `parallelism=4`).
- Users can select profiles dynamically based on their security requirements and hardware capabilities.

---

## 🛠️ Project Improvements

### ➤ **Metadata and Comments**
- Documentation and inline comments have been fully translated to English for clarity and global usability.
- Improved readability and maintainability of the codebase.

---

## 🛡️ Security Impact

| Aspect                  | Version 1.1.0              | Version 1.2.0                          |
|-------------------------|----------------------------|----------------------------------------|
| Streaming Performance   | Basic single-threaded I/O  | Optimized multithreading & buffered I/O|
| User Feedback           | Minimal                    | Detailed progress bar & speed feedback |
| Argon2 Configurability  | Static defaults            | Customizable security profiles         |
| Documentation           | Mixed language             | Fully standardized in English          |

---

## 📈 Compatibility and Migration

- Fully backward compatible with files encrypted by previous versions.
- No special migration steps required; users can immediately benefit from performance improvements.

---

## 📝 Final Remarks

CryptGuard version 1.2.0 significantly improves user experience through enhanced encryption speeds, dynamic resource management, and customizable security levels, continuing our commitment to strong security and high-performance encryption.
