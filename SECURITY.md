# 🛡️ CryptGuard Security Advisory

## ⚠️ Important Information

### Relative Security and User Responsibility

CryptGuard is developed to provide a robust encryption solution using:
- **ChaCha20Poly1305** for authenticated encryption,
- **Argon2id** for key derivation,
- **Reed-Solomon** for error correction.

However, no solution can guarantee absolute security. The use of CryptGuard should be accompanied by proper security practices and audits. The protected data remains the user's sole responsibility.

### External Audits and Reviews

We recommend:
1. Regular external security audits of CryptGuard.
2. Following best security practices and maintaining secure backups.

## 🔒 Security Best Practices

1. **User Responsibility and Relative Security**
   - Use strong passwords (ideally 12+ characters, including uppercase, lowercase, digits, and symbols).
   - Use “Password + Key-file” mode whenever possible to increase entropy.
   - Authentication includes double verification to reduce errors.

2. **Data Protection**
   - Sensitive data such as passwords and derived keys are handled carefully, and buffers are zeroized after use.
   - Metadata encryption includes original file extensions to ensure data integrity.

3. **Hidden Volumes and Key Rolling**
   - Hidden volumes separate fake and real data.
   - Use distinct passwords for each volume.
   - Re-Key (Key Rolling) allows changing the password for the real volume without compromising the hidden volume.

3. **Secure Environment**
   - Keep the operating system and dependencies updated.
   - Employ antivirus software, firewalls, and other protective tools.
   - Regularly backup data and metadata.

## ⚖️ Disclaimer

CryptGuard is provided without any warranty. Users are responsible for:
- Understanding the potential risks.
- Compatibility issues and incorrect configurations.
- Compliance with local laws and regulations.

## 📜 Legal and Regulatory Compliance

### Regulations
The use of encryption and security technologies may be subject to specific regulations varying by country. Users should verify compliance with local laws and regulations.

## 🆘 Support and Contact

To report vulnerabilities or security issues:
1. Do NOT open a public issue.
2. Email: [cryptguard737@gmail.com](mailto:cryptguard737@gmail.com).

---

This notice aims to inform users about limitations and best practices for using CryptGuard securely and responsibly, highlighting legal compliance requirements, security guidelines, and user responsibilities.
