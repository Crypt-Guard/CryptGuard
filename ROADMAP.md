## 🔐 CryptGuard - Features and RoadMap

### Main Features

The updated CryptGuard provides the following main functionalities:

| Option | Functionality                                 |
|--------|-----------------------------------------------|
| 1️⃣     | Encrypt Text                                  |
| 2️⃣     | Open File Selection Window                    |
| 3️⃣    | Decrypt File                                  |
| 4️⃣     | Encrypt Multiple Files                        |
| 5️⃣   | Generate Ephemeral Token                       |
| 6️⃣     | Create Hidden Volume (Plausible Deniability)  |
| 7️⃣     | Key Rolling - Normal Volume                   |
| 8️⃣     | Change Password of Real Volume (Hidden)       |
| 0️⃣     | Exit                                          |

---

### 🔒 Functionality Details

### 1️⃣ Encrypt Text

#### Operation Flow
1. **Input Text**
   - User inputs a message, password (double confirmation), and optionally a key file.
2. **Encryption Process**
   - Uses single-shot mode (`encrypt_data_single`).
   - Key derivation with Argon2id; encryption with ChaCha20Poly1305.
   - Encrypted metadata stored in a `.meta` file.

### 2️⃣ Open File Selection Window

#### Workflow
1. **Graphical Selection**
   - Opens a graphical window to conveniently select any file(s) for encryption or decryption from any location.
2. **Authentication:** Choose between "Password + Key-file" or "Password only."
3. **Size Check**
   - Files larger than a threshold (e.g., 10MB) use streaming mode (`encrypt_data_stream`). Smaller files use single-shot.
4. **Outcome**
   - Encrypted file saved with metadata preserving the original extension.

### 3️⃣ Decrypt File

#### Workflow
1. **Listing and Selection**
   - Shows available `.enc` files.
2. **Authentication**
   - Choose between "Password + Key-file" or "Password only."
3. **Processing**
   - Decrypts selected file; supports hidden volume via ephemeral token.
4. **Outcome**
   - Decrypted file restored with original extension (e.g., `.txt`, `.jpg`).

### 4️⃣ Encrypt Multiple Files

#### Workflow
1. **Selection**
   - User selects multiple files.
2. **Process**
   - ZIP compression, streaming mode for large ZIPs; single-shot for smaller ZIPs.
3. **Outcome**
   - Encrypted ZIP file stored with metadata.

### 5️⃣ Generate Token

#### Workflow
1. **Generation**
   - Produces a temporary token to secure the "real" data.
2. **Outcome**
   - Token displayed to user.

### 6️⃣ Create Hidden Volume (Plausible Deniability)

#### Workflow
1. **File Selection**
   - Two file sets: fake volume and real volume.
2. **Encryption**
   - Each set encrypted separately using `encrypt_data_raw_chacha`.
   - Volumes concatenated and encoded with Reed-Solomon.
   - Ephemeral token generated for real volume access.
3. **Outcome**
   - Hidden volume created with plausible deniability.

### 7️⃣ Key Rolling (Normal Volume)

#### Workflow
1. **File Selection**
   - File decrypted with old password.
2. **Re-encryption**
   - File re-encrypted with a new password.
3. **Outcome**
   - New encrypted file created, original extension preserved.

### 8️⃣ Change Real Volume Password (Hidden)

#### Workflow
1. **Hidden Volume Access**
   - Initially accesses fake volume metadata.
2. **Real Volume Decryption**
   - User enters current password for real volume.
3. **Re-Keying**
   - Real part decrypted in memory.
   - New password encrypts the real volume only.
4. **Outcome**
   - Sensitive data remains secure.

### 0️⃣ Exit

- Safely terminates the program.
