# 🛡️ Security Policy — CryptGuard v2 (v2.7.0)

CryptGuard v2 is a file-encryption tool and CG2 file format focused on practical security.  
This document explains what the software **does and does not** protect, safe-use guidance, and how to report vulnerabilities.

---

## Scope & Threat Model

**In scope**

- **Confidentiality & integrity of file contents** at rest and in transit (when using the CG2 container).
- **Tamper detection** (including end-truncation) and **parameter authenticity** (algorithm/KDF/nonce/expiry).
- **Type privacy** of the original file (extension is not exposed in the header).
- **Optional size obfuscation** via per-chunk padding.

**Out of scope**

- Compromised hosts (malware, keyloggers, root/admin, live memory scraping).
- Side-channel and traffic analysis beyond optional padding.
- OS and filesystem metadata (file names, directory paths, timestamps) **outside** the CG2 container.
- Password strength chosen by the user.
- Long-term cryptanalytic breakthroughs against the underlying primitives.

---

## What CryptGuard Guarantees (v2.7.0)

- **Chunked AEAD**: AES-256-GCM, ChaCha20-Poly1305, and XChaCha20-Poly1305 with **unique nonces per chunk** (random base + counter).
- **Authenticated header (AAD)**: The CG2 header (algorithm, Argon2id parameters, nonce/IV, expiration) is **authenticated**. Any tampering/downgrade fails decryption.
- **Anti-truncation for AEAD**: A signed footer **`END0`** authenticates `(chunk_count, total_plain_len)`. Cutting exactly on a chunk boundary is detected.
- **CTR integrity**: AES-256-CTR uses **encrypt-then-MAC** (HMAC-SHA256) with keys split via HKDF, plus **`SIZ0`** for the real plaintext size.
- **Encrypted original extension**: The footer includes **`NAM0`** (the original extension **encrypted**). Decrypt restores the true extension even if the `.cg2` file was renamed.
- **Optional size padding**: Per-chunk zero-padding (Off / 4 KiB / 16 KiB / 64 KiB / 1 MiB). On decrypt, the output is **truncated** to the true size stored in the footer.
- **KDF**: **Argon2id** with a fresh random **salt** per file; parameters are authenticated. Profiles: *Fast / Balanced / Hard*.

> Memory-locking (mlock/VirtualLock) is **best-effort**; it reduces, but cannot eliminate, paging of sensitive data.

---

## Known Limitations & Safe-Use Guidance

1. **Choose strong passphrases**  
   Use 12+ characters or 4–6 random words. Password strength dominates real-world security.

2. **KDF profiles**  
   Start with **Balanced**. Increase to **Hard** if your system has sufficient RAM/CPU. Avoid reducing Argon2id parameters unless you know the trade-offs.

3. **Pad size** (privacy vs. size)  
   - Default: **4 KiB** (good balance).  
   - 16–64 KiB: stronger size obfuscation, larger `.cg2`.  
   - Off: smallest `.cg2`, reveals exact size.  
   Decrypt always restores the exact original size.

4. **Algorithms**  
   Prefer **AES-256-GCM** or **XChaCha20-Poly1305** when available. AES-CTR is supported **with HMAC** and `SIZ0` for integrity.

5. **Expiration**  
   Optional header field; it is authenticated and enforced prior to opening plaintext.

6. **Environment hygiene**  
   Keep OS and dependencies up to date. Avoid decrypting secrets on untrusted machines.

7. **Backups**  
   Keep redundant backups of `.cg2` files. Any corruption or tampering will make verification fail by design.

8. **Windows/UAC**  
   Do **not** run the GUI as Administrator if you need drag-and-drop (Windows blocks DnD into elevated apps).

---

## Version Compatibility

- **CG2 v4 (current)**: authenticated header, `NAM0` encrypted extension, AEAD footer `END0`, CTR `SIZ0` + HMAC `TAG0`.  
- **CG2 v3 (legacy)**: readable; decryption still works (legacy extension, if present, is honored).  
- Very old CTR artifacts without HMAC are **not supported**; re-encrypt to the current format to gain full integrity protection.

Supported lines:

| Version | Status     | Notes                           |
|--------:|------------|---------------------------------|
| 2.3.x   | Supported  | Current feature & security fixes |
| < 2.7   | Not supported | Please upgrade to ≥ 2.7.0     |

---

## Reporting a Vulnerability (Responsible Disclosure)

- **Please do not open public issues** for security problems.
- Contact: **cryptguard737@gmail.com**  
  Include:
  - A clear description of the issue and its impact
  - Steps to reproduce, PoC inputs/outputs, and logs (if available)
  - Your OS, CryptGuard version (e.g., 2.7.0), and environment details

---

## Legal & Export Compliance

- See **README** for export notes. Source code is publicly available encryption; binary releases are generally treated as **ECCN 5D002 / License Exception ENC**.  
- Users are responsible for complying with all applicable laws and sanctions.  
- CryptGuard is provided **“AS IS”**, without warranties of any kind (see `LICENSE.txt`).

---

Stay safe, use strong passphrases, and keep your system up to date.
