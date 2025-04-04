# CryptGuard – Detailed Technical README

**CryptGuard** is a data encryption tool with support for **hidden volumes** to provide **plausible deniability**. Developed in Python, it allows the creation of encrypted volumes in which confidential data can be stored with strong cryptographic protection. Its main differentiator is the ability to create a second hidden volume within the main volume, so that even under duress the user can disclose only the external volume without revealing the existence of more sensitive data.

---

## Recent Updates in v1.0

This version introduces several important changes and refinements:

- **ChaCha20-Poly1305 Support**  
  Chunk-based encryption can now be done with ChaCha20-Poly1305, removing the plaintext checksum that was previously in use. This ensures an authenticated encryption approach without leaking any plaintext hash.

- **Fallback for Argon2id**  
  If a `MemoryError` occurs during key derivation, CryptGuard now tries lower Argon2id memory parameters automatically. This means it can adapt to systems with less RAM while still preserving robust security.

- **Atomic Metadata Writing**  
  The `.meta` file is now written via a temporary file and then replaced, preventing corruption in case of a crash or interruption mid-write.

- **Improved Streaming**  
  Large files are encrypted/decrypted in continuous chunks, so memory usage is kept low. If an error occurs during streaming, partial or temporary files are removed, avoiding leftover corrupted data.

- **Exception Handling**  
  Errors (like wrong passwords or I/O failures) are now more gracefully managed, ensuring incomplete outputs are cleaned up and sensitive variables are zeroed out as soon as possible.

- **Single `.exe` Distribution**  
  You can now build a single executable with PyInstaller. Users on Windows can run CryptGuard with no extra setup.

Below is the complete, **detailed, and updated** explanation of how CryptGuard is structured and how it works, reflecting all these enhancements.

---

## Introduction

CryptGuard was designed to protect confidential data at rest, providing an additional security layer through a hidden volume. Its main features include:

- **Strong Encryption**: Uses modern algorithms (like AES with 256-bit keys or an equivalent secure cipher) and Argon2-based key derivation to ensure data confidentiality. Newer versions can employ **ChaCha20-Poly1305** as well.
- **Hidden Volume**: Allows creating a secret inner volume within an encrypted volume, enabling plausible deniability in coercive situations.
- **Secure Key Derivation**: Employs Argon2 (a robust key derivation function) to convert passwords into cryptographic keys, making brute-force attacks more difficult. A fallback mechanism now adapts memory usage if the system has limited RAM.
- **Large File Handling**: Supports **streaming** encryption, splitting data into chunks to process large files without loading them entirely into memory.
- **Modular Interface**: Code organized into independent modules, facilitating maintenance and extensions for developers.
- **Removal of Plaintext Checksums**: Ensures no accidental leakage of hashes from the encrypted data or blocks.

This technical README is intended for developers who want to understand CryptGuard’s internal workings to modify or update it. Below, we detail the code structure, explain how the hidden volume is implemented, and describe the role of each module, with usage examples and best practice tips for feature expansion.

---

## Code Structure

The project is organized into multiple Python modules, each responsible for a part of the CryptGuard logic. Below is a general overview of the files and the responsibility of each module:

- **`password_utils.py`** – Responsible for password validation functions and managing authentication, including checking for a key file when used.
- **`rs_codec.py`** – Implements Reed-Solomon encoding and decoding to ensure data integrity and provide error correction mechanisms for encrypted chunks.
- **`config.py`** – Defines global settings and constants used throughout the system (key sizes, Argon2 parameters, block size, etc.).
- **`utils.py`** – Generic utility functions used across various modules (e.g., byte manipulation, conversions, generating secure random values, etc.).
- **`argon_utils.py`** – Logic for key derivation using Argon2. Contains functions to generate the cryptographic key from the user’s password and a salt, now supporting fallback if `MemoryError` arises.
- **`chunk_crypto.py`** – Implements chunk-based data encryption and decryption. Provides low-level functions to encrypt/decrypt segments of a file using the derived key. Now fully supports ChaCha20-Poly1305 (or AES) in authenticated modes, and **no plaintext checksum** is stored.
- **`metadata.py`** – Defines the structure of the encrypted volume’s metadata (header). This module handles creating and interpreting the volume header, including information such as salt, KDF parameters, hidden volume size, etc. Now written atomically to avoid corruption.
- **`hidden_volume.py`** – Manages hidden volume logic. Functions for creating an encrypted volume (with or without a hidden volume) and for accessing/extracting the hidden volume inside the external volume.
- **`streaming.py`** – Provides **streaming** encryption mechanisms (continuous flow). Used for reading or writing encrypted data in parts, useful for not loading entire files into memory.
- **`single_shot.py`** – Offers **single-shot** encryption functions that process the entire data at once. Suitable for smaller files or straightforward operations.
- **`main.py`** – Application entry point (CLI). Parses command-line arguments and coordinates operations such as creating volumes, encrypting, or decrypting files, using the modules above.
- **`__init__.py`** – Initializes the `cryptguard` package. Typically empty or used to expose the package’s public interfaces (e.g., convenient imports or version information).

This modular separation makes the code easier to understand and maintain: each component handles a specific aspect (configurations, encryption, hidden volume, etc.), allowing developers to modify parts in isolation without impacting the entire system.

---

## Hidden Volume and Security

The **hidden volume** is CryptGuard’s primary advanced security feature. It allows highly sensitive data to be stored within an encrypted volume in such a way that the very existence of these data is concealed. Below, we explain how it’s implemented and how it protects the data:

- **Plausible Deniability Concept**: When creating a volume with concealment support, the user sets two passwords – one for the external volume (less sensitive or more innocuous data) and another for the hidden internal volume (highly sensitive data). If forced to divulge a password, the user can provide only the external volume’s password. Anyone with that password gains access only to the external volume’s data, while the hidden volume remains inaccessible and undetectable.
- **Hidden Volume Implementation**: CryptGuard uses a single encrypted container file. Inside this container:  
  - The **external volume** occupies the initial portion of the file and has its own metadata header and encrypted data region.  
  - The **hidden volume** is stored in a reserved portion of the same file (usually at the end or in areas unused by the external volume). Its data are also encrypted and can only be interpreted using the second password.  
  The random filler ensures that without the correct password, the hidden portion appears as mere random data.
- **Data Protection**: Both volumes (external and hidden) use strong encryption. The password is never used directly as a key; instead, `argon_utils.py` applies Argon2 plus a random salt to derive the encryption key, making brute-force attacks harder. 
- **Metadata Isolation**: The volume metadata (defined in `metadata.py`) includes only the information needed for the volume it pertains to. External metadata decrypts properly with the external password, hidden metadata with the hidden password. No explicit “hidden volume indicator” is present in the external header, preserving deniability.
- **Volume Opening Operation**: On mounting an encrypted volume, CryptGuard attempts to decrypt the metadata with the user’s password. If it succeeds, that password is for the external volume; if it fails, CryptGuard may try the region intended for the hidden volume. If that decrypts successfully, it is recognized as the hidden volume. If both fail, the password is incorrect or the file is not a valid container.
- **Integrity and Confidentiality**: Encryption modes supporting authentication (AES-GCM or ChaCha20-Poly1305) ensure data integrity. If not used, it may rely on additional measures or Reed-Solomon for partial error correction.  
- **Overwrite Protections**: If the external volume is mounted for writing, a user aware of the hidden volume can supply both passwords so the software ensures the external data doesn’t overwrite the hidden region. If that feature is not fully implemented, developers must be cautious to avoid damaging hidden data.

In summary, CryptGuard’s security strategy combines strong encryption with careful storage design to provide plausible deniability. Even if an adversary obtains the container, only the external password is known or shown, leaving the second hidden volume undiscovered unless the user chooses to reveal it.

---

## How Each Module Works

This section provides an internal overview of each CryptGuard module and how a developer might modify or extend them. Understanding how these components interact is essential to make safe changes without introducing regressions. The usage examples help illustrate how the modules work together.

### 1. `config.py` – Global Settings

The `config.py` module consolidates global constants and configuration parameters used throughout the application. These include:

- **Sizes and Lengths**: e.g., Argon2 salt size, key length (256 bits), encryption block size, etc.
- **Argon2 Parameters**: Default values for time cost, memory cost, and parallelism.
- **Encryption Algorithms**: Possibly references to ciphers like AES, ChaCha20, or others, plus block or nonce sizes.
- **Other**: Info about the volume header size, format version, etc.

**How it works**: Other modules import values from `config.py` to ensure consistency. For example, `argon_utils.py` calls `config.py` for Argon2 memory usage, or `chunk_crypto.py` references the block size. Changing a constant in `config.py` affects the entire program.

**How to modify**: If you want to adjust Argon2 or switch from AES to ChaCha20-Poly1305 by default, do so here. Make sure any references to older algorithms or block sizes are updated as well. Consider that changing these parameters can break backward compatibility with older volumes unless you implement a versioning/migration strategy in `metadata.py`.

---

### 2. `utils.py` – Utility Functions

`utils.py` contains auxiliary, general-purpose functions that do not specifically fit into the other components. For example:

- **Secure Random Generation** (using `os.urandom` or `secrets`).
- **Byte and String Manipulation**: Conversions for data encoding, clearing buffers, or small hashing tasks. 
- **Error or Logging**: Possibly custom exception handling or small logging stubs.

**How it works**: Modules like `hidden_volume.py` or `metadata.py` call these to generate random salts or do conversions. Keeping them in a single file avoids duplicating code across modules.

**How to modify**: Add new helper functions if they are used in multiple places. Make sure that changes do not break other modules that rely on existing behaviors.

---

### 3. `argon_utils.py` – Key Derivation (Argon2)

This module implements key derivation using **Argon2**. Argon2 is a state-of-the-art password hashing function that is memory- and time-intensive, thwarting brute-force attempts. 

Key aspects:

- **Derivation Function**: Typically something like `derive_key(password, salt)` which uses Argon2 with parameters from `config.py`.
- **Fallback Logic**: If a `MemoryError` arises, it attempts to reduce Argon2 memory cost and tries again, a new feature that ensures compatibility with lower-RAM systems.
- **Secure Password Handling**: Usually it tries to limit how long password material stays in memory, although that can be challenging in Python.

**How it works**: Upon creating or opening a volume, `argon_utils.py` receives the user’s password and the container’s stored salt. After the password is read in, Argon2 processes them to produce a 256-bit (or user-defined) key. This key is used by `chunk_crypto.py` to actually encrypt or decrypt the data.

**How to modify**: If you want to adopt a new password-based KDF, or tweak Argon2 parameters (like increasing memory cost or time cost), do it here. Test thoroughly to ensure volumes remain readable. For advanced usage, store Argon2 parameters in the volume’s metadata so each volume can have distinct derivation settings.

---

### 4. `chunk_crypto.py` – Block-Based Data Encryption

`chunk_crypto.py` does the low-level encryption and decryption of data in blocks (“chunks”). Historically it might have used AES with some mode, but the system can now also handle **ChaCha20-Poly1305** for authenticated encryption without storing plaintext checksums.

Key features:
- **Cipher Initialization**: Each chunk might have its own nonce/IV, derived from a counter or read from the file.
- **Encrypt/Decrypt Chunks**: Functions like `encrypt_chunk` and `decrypt_chunk` take raw bytes and a key, plus an IV or index, returning encrypted or decrypted data.
- **No Plaintext Checksum**: The older approach of storing an SHA-256 of the plaintext in cleartext was removed. Now, if using AEAD (e.g. ChaCha20-Poly1305 or AES-GCM), each chunk includes an authentication tag internally.

**How it works**: Higher-level modules handle reading or writing data in the correct block size, then pass each block to `chunk_crypto.py`. The results are stored or streamed to disk. For decryption, the same modules supply the correct key and nonce so chunk_crypto can recover plaintext.

**How to modify**: If you’d like to implement new modes (e.g., AES-CBC with HMAC, or a custom approach) or additional AEAD ciphers, it goes here. Ensure the higher-level code in `streaming.py` or `single_shot.py` knows how to handle block sizes or tags. Because the older plaintext checksums are gone, you should rely on a robust AEAD approach for integrity checks.

---

### 5. `metadata.py` – Encrypted Volume Metadata

`metadata.py` defines how the volume header is structured, storing necessary info for mounting either the external or hidden volume. It can contain:

- **Magic/Version**: Identifying signature for CryptGuard volumes.
- **Salt**: For Argon2 key derivation.
- **Argon2 Parameters**: If each volume can store its own parameters.
- **Allocation Info**: Possibly the size or offset of the hidden volume (though not in the external header if you want to keep it concealed).
- **Checksum/Signature**: Possibly checks to confirm the header is valid once decrypted.
- **Atomic Write**: Now, the `.meta` file is written using a temporary file and renamed, preventing partial writes from corrupting the file.

**How it works**: The main code typically calls `metadata.py` to build a structure, then encrypts it with the Argon2-derived key and writes it to the file start (or a separate `.meta`). For the hidden volume, an equivalent or separate area is used. On opening, the code reads, decrypts, and parses this structure. If it matches expected “magic,” the user knows the password was correct.

**How to modify**: If you add a new field (like a “cipher algorithm” or “creation date”), incorporate it in `metadata.py` and handle it in the serialization/deserialization methods. Changing the format can break older volumes, so consider versioning if your changes are not backward-compatible.

---

### 6. `hidden_volume.py` – Hidden Volume Management

This module coordinates creation and access of the hidden volume within a container. Key functions often include:

- **`create_volume(...)`**: Build a container file that includes the external volume, and optionally a hidden volume if a second password is provided. Writes random filler across the unused portions so an attacker cannot see anything distinctive if they only have the external password.
- **`open_volume(...)`**: Accepts a password, tries to decrypt the external or hidden metadata. If one decrypts successfully, returns an object representing that volume. If both fail, the password is invalid or the file is not recognized.
- **Preventing Overwrites**: If the user supplies both passwords, the code can forbid writing external data in the hidden region. This feature may not be fully implemented yet, but it’s a typical approach from other plausible-deniability systems.

**How it works**: The code here orchestrates calls to `argon_utils` (to derive keys), `metadata.py` (to build or read header info), and `chunk_crypto` or `streaming` (to manage data). The hidden volume is either at the end or in a “reserved offset,” making it invisible to the external volume. Everything is encrypted such that random data in the file could either be free space or hidden volume content.

**How to modify**: If you want multiple hidden volumes, or to store the hidden volume in an unusual position, this is where you do it. If you add advanced overwrite protection (ensuring the external volume never corrupts the hidden data), also do it here. Thoroughly test your changes to ensure you don’t inadvertently expose the existence of the hidden region.

---

### 7. `streaming.py` – Streaming Encryption

`streaming.py` enables reading/writing data incrementally:

- **Encrypting**: Splits plaintext into blocks, calls `chunk_crypto.encrypt_chunk` on each, and writes them out. Or does the reverse for decryption. 
- **Memory Efficiency**: The user never needs to hold the entire file in RAM. Good for multi-gigabyte files.
- **Error Handling**: On failures, partially written blocks can be discarded or the file removed. This update also cleans up temporary files to avoid leftover corrupted data.

**How it works**: Called from `hidden_volume.py` or `main.py` to process large data. It might have functions like `encrypt_stream(input_file, output_file, key)` or `decrypt_stream(...)`.

**How to modify**: Typically you won’t unless you add new cipher modes needing different chunk handling or want partial random-access reading. If you want parallel chunk encryption for performance, you could adapt it, but watch concurrency issues in Python (the GIL or the stateful nature of certain modes).

---

### 8. `single_shot.py` – One-Shot Operations

`single_shot.py` handles the simpler scenario: load the entire data in memory, encrypt it in one pass, and save it. Good for small or moderate files. 

- **Encrypt/Decrypt**: Possibly `encrypt_data`, `decrypt_data`, `encrypt_file`, `decrypt_file`.
- **Memory**: For large files, it’s less efficient than `streaming.py`.

**How it works**: Under the hood, it might still rely on `chunk_crypto`, but with a single chunk or one read of the entire data. Then it writes the ciphertext out, or returns it to the caller.

**How to modify**: If you want to unify code so single-shot also uses the streaming logic behind the scenes (just reading everything at once), you can do that. Or if you want features like AES-GCM with a combined final tag, ensure the chunk logic accommodates that. 

---

### 9. `main.py` – CLI and Initialization

`main.py` is the script that runs CryptGuard’s command-line interface. Common tasks:

- **Argument Parsing**: Might use `argparse` for subcommands like `create`, `open`, `encrypt`, `decrypt`, etc.
- **Password Prompts**: Ensures user does not pass a password in plain text if not desired. Could use `getpass.getpass()` for safer input.
- **Coordination**: Ties everything together by calling the relevant functions in `hidden_volume`, `streaming`, or `single_shot`. 
- **Error Handling**: Prints meaningful messages, catches exceptions from other modules, removes partial files if something goes wrong.

**How it works**: The user runs `python main.py --help` or a specific command. `main.py` interprets those arguments, calls the correct code to do volume creation, encryption, etc., and provides status feedback.  

**How to modify**: Add new subcommands or flags (like a `--progress` option for streaming), or integrate the hidden volume creation with some specialized parameters (size, offset, etc.). If you want to offer a user experience with optional hidden volume creation in a single step, you can do it here. Also you can add logic for building the final `.exe` via PyInstaller if you want a specialized build script or instructions.

---

## Final Considerations

CryptGuard provides a solid foundation for volume encryption with plausible deniability. With the new improvements:

- **ChaCha20-Poly1305** or AES-GCM can ensure authenticity for each block.
- **Plaintext checksums** are removed, eliminating potential leakage of sensitive data.
- **Argon2 fallback** ensures it runs on various hardware configurations.
- **Atomic metadata** writes reduce corruption risk.
- **Exception handling** cleans up partial writes or leftover temporary files.

### Testing and Verification

- **Unit and Integration Tests**: Each module should have tests verifying correctness. This includes negative tests (incorrect password, partial data, forced corruption). 
- **Security Audits**: Invite external reviews or pen tests to confirm that hidden volumes remain hidden and that cryptographic elements are robustly implemented.
- **Upgrade Paths**: If you change how volumes are structured or how keys are derived (e.g. adopting new Argon2 parameters or a different cipher as default), handle older volumes carefully. The metadata version field can help detect which method is needed.

### Potential Future Enhancements

- **GUI**: A graphical interface could be built on top of these modules, making it friendlier for non-technical users.
- **Multiple Hidden Volumes**: Expand the concept of plausible deniability by supporting more than one hidden region, each with its own password, though it can complicate offset management.
- **Dynamic Growth**: Possibly allow resizing volumes or hidden areas if you track free space carefully.
- **Integrity Checks**: If not using AEAD for each block, add an HMAC or a global authentication method to detect tampering. Reed-Solomon helps with corruption but not malicious modifications.
- **Signed Executables**: If distributing a `.exe`, code-signing might reduce user friction with antivirus and SmartScreen warnings.

By understanding the roles and responsibilities of each module, developers can confidently add new features or improve existing logic without jeopardizing CryptGuard’s security. The design fosters separation of concerns (Argon2 in `argon_utils.py`, chunk-based encryption in `chunk_crypto.py`, volume-level logic in `hidden_volume.py`, etc.), making the system more maintainable and extensible. Combined with cautious testing and updates, CryptGuard can remain a robust, reliable encryption tool for secure data storage under plausible deniability scenarios.

---

**End of Updated README – CryptGuard v1.0**  
Enjoy a more secure and efficient CryptGuard with this latest release! For any questions or enhancements, check out the [contribution guidelines](CONTRIBUTING.md) and [security policy](SECURITY.md).
