# 🛡️ CryptGuard Security Policy

CryptGuard provides powerful encryption features, but no software can guarantee absolute security under all conditions. This document outlines how we handle security matters, recommends safe usage practices, and clarifies user responsibility.

---

## ⚠️ Disclaimer and User Responsibility

- **No Warranty**: CryptGuard is provided “as is,” without warranties or guarantees.  
- **User Accountability**: You, the user, are fully responsible for how you utilize CryptGuard. Misconfiguration or weak passwords can compromise your data.  
- **Legal Compliance**: CryptGuard must be used in accordance with local laws and regulations concerning cryptographic software.

---

## 🔐 Best Practices

1. **Strong Passwords**  
   - Choose passwords of 12+ characters (mix of uppercase, lowercase, digits, symbols).  
   - Consider using **“Password + Key-file”** mode for increased entropy.

2. **Argon2id Key Derivation**  
   - CryptGuard employs Argon2id to slow down brute force attacks.  
   - If your system has limited RAM, fallback logic reduces memory usage. However, you remain responsible for verifying your machine’s resources.

3. **Hidden Volumes**  
   - Real volumes require an **ephemeral token** plus a distinct password.  
   - If you lose the token, recovery of the real volume is impossible.  
   - Present only the decoy password (and data) under coercion to maintain plausible deniability.

4. **File Integrity and Metadata**  
   - Always keep the `.enc` file and its `.meta` together.  
   - Reed-Solomon can correct minor corruptions but does not replace secure backups.

5. **Keep Systems Updated**  
   - Regular OS and dependency updates reduce vulnerabilities.  
   - Use antivirus and firewalls where appropriate.

6. **Backup Strategy**  
   - Store encrypted files and their metadata in multiple secure locations.  
   - Losing the `.meta` file will make decryption infeasible.

---

## 🔍 Reporting Vulnerabilities

- **Confidential Disclosure**: If you discover a security issue, do NOT open a public GitHub issue.  
- **Contact**: Email the details to [cryptguard737@gmail.com](mailto:cryptguard737@gmail.com) (or any maintained contact if available).  
- We value responsible disclosure and will address legitimate concerns quickly.

---

## ⚖️ Legal Compliance

1. **Export/Import Laws**  
   - Cryptographic software may be subject to export and import restrictions in some jurisdictions.  
   - You must ensure compliance with your local regulations.

2. **Usage Restrictions**  
   - Any unauthorized or criminal usage of CryptGuard is strictly the user’s responsibility.  
   - The CryptGuard team disclaims liability for unlawful or malicious usage of the software.

---

## 🏗 Maintainer Responsibilities

- **Prompt Patching**: The maintainers will release fixes for discovered vulnerabilities in a timely manner.
- **Transparency**: If a security event affects the integrity of user data, we will communicate openly via the project’s releases or advisories.

---

By using CryptGuard, you acknowledge the **disclaimer of warranty** and accept that you are solely responsible for data safeguarding and compliance with the applicable laws. When in doubt, seek professional security audits or legal advice.

Stay safe, secure, and use strong passwords!

---
