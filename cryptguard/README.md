**CryptGuard** is a data encryption tool with support for **hidden volumes** to provide **plausible deniability**. Developed in Python, it allows the creation of encrypted volumes in which confidential data can be stored with strong cryptographic protection. Its main differentiator is the ability to create a second hidden volume within the main volume, so that even under duress the user can disclose only the external volume without revealing the existence of more sensitive data.

## Introduction

CryptGuard was designed to protect confidential data at rest, providing an additional security layer through a hidden volume. Its main features include:

- **Strong Encryption**: Uses modern algorithms (like AES with 256-bit keys or equivalent) and Argon2-based key derivation to ensure data confidentiality.
- **Hidden Volume**: Allows creating a secret inner volume within an encrypted volume, enabling plausible deniability in coercive situations.
- **Secure Key Derivation**: Employs Argon2 (a robust key derivation function) to convert passwords into cryptographic keys, making brute-force attacks more difficult.
- **Large File Handling**: Supports **streaming** encryption, splitting data into chunks to process large files without loading them entirely into memory.
- **Modular Interface**: Code organized into independent modules, facilitating maintenance and extensions for developers.

This technical README is intended for developers who want to understand CryptGuard’s internal workings to modify or update it. Below, we detail the code structure, explain how the hidden volume is implemented, and describe the role of each module, with usage examples and best practice tips for feature expansion.

## Code Structure

The project is organized into multiple Python modules, each responsible for a part of the CryptGuard logic. Below is a general overview of the files and the responsibility of each module:

- **`password_utils.py`** – Responsible for password validation functions and managing authentication, including checking for a key file when used.
- **`rs_codec.py`** – Implements Reed-Solomon encoding and decoding to ensure data integrity and provide error correction mechanisms for encrypted chunks.
- **`config.py`** – Defines global settings and constants used throughout the system (key sizes, Argon2 parameters, block size, etc.).
- **`utils.py`** – Generic utility functions used across various modules (e.g., byte manipulation, conversions, generating secure random values, etc.).
- **`argon_utils.py`** – Logic for key derivation using Argon2. Contains functions to generate the cryptographic key from the user’s password and a salt.
- **`chunk_crypto.py`** – Implements chunk-based data encryption and decryption. Provides low-level functions to encrypt/decrypt segments of a file using the derived key.
- **`metadata.py`** – Defines the structure of the encrypted volume’s metadata (header). This module handles creating and interpreting the volume header, including information such as salt, KDF parameters, hidden volume size, etc.
- **`hidden_volume.py`** – Manages hidden volume logic. Functions for creating an encrypted volume (with or without a hidden volume) and for accessing/extracting the hidden volume inside the external volume.
- **`streaming.py`** – Provides **streaming** encryption mechanisms (continuous flow). Used for reading or writing encrypted data in parts, useful for not loading entire files into memory.
- **`single_shot.py`** – Offers **single-shot** encryption functions that process the entire data at once. Suitable for smaller files or straightforward operations.
- **`main.py`** – Application entry point (CLI). Parses command-line arguments and coordinates operations such as creating volumes, encrypting, or decrypting files, using the modules above.
- **`__init__.py`** – Initializes the `cryptguard` package. Typically empty or used to expose the package’s public interfaces (e.g., convenient imports or version information).

This modular separation makes the code easier to understand and maintain: each component handles a specific aspect (configurations, encryption, hidden volume, etc.), allowing developers to modify parts in isolation without impacting the entire system.

## Hidden Volume and Security

The **hidden volume** is CryptGuard’s primary advanced security feature. It allows highly sensitive data to be stored within an encrypted volume in such a way that the very existence of these data is concealed. Below, we explain how it’s implemented and how it protects the data:

- **Plausible Deniability Concept**: When creating a volume with concealment support, the user sets two passwords – one for the external volume (less sensitive or more innocuous data) and another for the hidden internal volume (highly sensitive data). If forced to divulge a password, the user can provide only the external volume’s password. Anyone with that password gains access only to the external volume’s data, while the hidden volume remains inaccessible and undetectable, since its data appear random within the encrypted file.
- **Hidden Volume Implementation**: CryptGuard uses a single encrypted container file. Inside this container:
  - The **external volume** occupies the initial portion of the file and has its own metadata header and encrypted data region.
  - The **hidden volume** is stored in a reserved portion of the same file (usually at the end or in areas unused by the external volume). Its data are also encrypted and can only be interpreted using the second password.  
  Importantly, the hidden volume’s space is filled with random data when the volume is created, so that without the correct password, it is indistinguishable from random free space.
- **Data Protection**: Both volumes (external and hidden) use strong encryption. The user’s password is never used directly as a key; instead, the derivation module (`argon_utils.py`) applies Argon2 (a robust KDF) along with a random salt (stored in the header) to generate the encryption key. This makes brute-force attacks much harder, because Argon2 imposes a high computational cost for each password attempt.
- **Metadata Isolation**: The volume metadata (defined in `metadata.py`) includes the information needed to mount/open the volume: an identifier or version number, the Argon2 salt, Argon2 parameters (processing time, memory, etc.), hidden volume size, and so on. These external volume metadata are stored at the start of the container file, encrypted with the key derived from the external password. The hidden volume’s metadata is stored separately (for example, in another known area of the file, possibly right after the external volume space or at the end of the file), encrypted with the key derived from the hidden password. Thus, knowing only the external password allows decrypting only the external volume metadata – the hidden volume’s metadata remains inaccessible without the second password.
- **Volume Opening Operation**: When opening an encrypted volume, CryptGuard attempts to decrypt the metadata header using the provided password. If the password matches the external volume, the metadata will decrypt correctly (validated by an integrity field or internal signature), and the system mounts the external volume. If the password matches the hidden volume, the external header decryption will fail; the software may then attempt to decrypt the hidden volume’s metadata area with that password. If valid, it mounts the hidden volume. If neither attempt produces valid metadata, the password is deemed incorrect. This process ensures that an attacker with only the external password cannot detect or mount the hidden volume.
- **Integrity and Confidentiality**: All stored data, in both the external and hidden volumes, is encrypted. Optionally, each data block can include integrity/authenticity checks (for instance, authenticity tags or HMACs) to detect unauthorized changes in the encrypted data. (Note: If CryptGuard uses an authenticated cipher such as AES-GCM, integrity comes included; otherwise, this feature could be added via HMAC in future improvements).
- **Write Restrictions on the External Volume**: Once a hidden volume is created inside a container, it is crucial that the external volume not overwrite hidden volume data. When creating a hidden volume, CryptGuard explicitly reserves a portion of the file for it. Writing data to the external volume must be restricted to its allocated space. In scenarios where the external volume can be mounted for writing, a recommended practice (inspired by VeraCrypt/TrueCrypt) is also to request the hidden volume password during the external mount so that the software can avoid accidentally writing to areas occupied by the hidden volume. If CryptGuard has not yet implemented this dynamic protection, **developers should use caution** when adding such a feature to ensure that the hidden volume is not corrupted.

In summary, CryptGuard’s security strategy combines strong encryption with careful storage design to provide plausible deniability. Even if an adversary obtains the encrypted file, without the correct password they see only random data; and even with the external password, there is no indication that a second volume exists. For the legitimate user, however, accessing hidden data is seamless upon entering the secondary password.

## How Each Module Works

This section provides an internal overview of each CryptGuard module and how a developer might modify or extend them. Understanding how these components interact is essential to make safe changes without introducing regressions. The usage examples help illustrate how the modules work together.

### config.py – Global Settings

The `config.py` module consolidates global constants and configuration parameters used throughout the application. These include, among others:

- **Sizes and Lengths**: For example, the size of the Argon2 salt in bytes, the length of the derived key (e.g., 256 bits), encryption block size, etc.
- **Argon2 Parameters**: Default values for iterations (time), memory, and parallelism used in key derivation. For example, `ARGON_T_COST` (time cost / number of iterations), `ARGON_M_COST` (memory in KiB), `ARGON_PARALLELISM` (number of threads).
- **Encryption Algorithms**: The specification of the default algorithm and operating mode (e.g., AES in XTS mode or GCM), and block size. If the project uses a crypto library, you might define strings or identifiers here to select the cipher.
- **Other**: The size of the volume’s metadata (header), the format’s version identifier, and any default flags or options.

*How it works:* These values are imported by other modules to ensure consistency. For instance, `argon_utils.py` looks to `config.py` to determine which salt size and Argon2 parameters to use, and `chunk_crypto.py` may rely on the block size constant defined here.

*How to modify:* Developers can adjust parameters in `config.py` to update global settings. For example, increasing Argon2’s cost (to strengthen security against brute-force attacks) or switching the encryption algorithm (if implementing ChaCha20-Poly1305 instead of AES). Such changes affect the entire system, so it’s important to check compatibility – volumes created with older settings might need migration if the format changes (e.g., changing header size or algorithm should come with a version increment and possibly conversion procedures). Keep `config.py` as the single source of truth to avoid “magic numbers” spread throughout the code.

### utils.py – Utility Functions

`utils.py` contains auxiliary, general-purpose functions that do not specifically fit into the other components. Examples of functionalities that may appear in this module:

- **Secure Random Data Generation**: A function to generate random bytes (e.g., using `os.urandom()` or a crypto library) for a variety of purposes such as salt, IV (initialization vector), or padding.  
- **Byte and String Manipulation**: Converting addresses or integers to bytes and vice versa, padding data for block alignment, formatting size values (e.g., converting a size in MB to bytes).
- **Cryptographic Support Functions**: For instance, secure memory cleaning (overwriting plaintext buffers after use) or calculating hashes/HMACs, if needed in various places.
- **Error and Logging Handling**: Possibly utilities for logging cryptographic events or throwing custom exceptions (e.g., a specific exception for “incorrect password” or “corrupted data”).

*How it works:* `utils.py` acts as a support library for the other modules. For example, when creating a volume, `hidden_volume.py` can call `utils.py` to generate the random salt for the header. If there’s a need to convert representations (like turning a password into a specific encoding prior to key derivation), it could be handled in utils. Having them isolated facilitates unit testing and avoids code duplication.

*How to modify:* When adding new functionalities used by multiple modules, consider implementing them here. For instance, if you plan to include an integrity verification function repeated across different places, put it in utils. Make sure to write generic, well-tested functions, since a bug here can affect many parts of CryptGuard. If you change an existing function (such as the random generator), ensure it continues to use cryptographically secure sources. In short, `utils.py` should contain **purely utility** functions – modify it as necessary, but avoid placing high-level logic here (that belongs in the main modules).

### argon_utils.py – Key Derivation (KDF)

This module implements key derivation using the **Argon2** algorithm, one of today’s most secure password-based key derivation functions. Argon2 protects against brute-force attacks by imposing a high computational and memory cost for each key discovery attempt.

Key aspects of `argon_utils.py`:

- **Derivation Function**: Likely the main function here is something like `derive_key(password: str, salt: bytes) -> bytes`. It uses the parameters set in `config.py` (e.g., iterations, memory, key length) to run Argon2 and produce the encryption key from the provided password.
- **Supporting Library**: Internally, the implementation may use a Python library like `argon2-cffi` or a similar solution, or it might call a low-level function. The parameters (password, salt, t_cost, m_cost, parallelism) are passed in as defined by `config.py`.
- **Random Salt**: Salt generation is *not* done here; the salt is likely generated via `utils.py` when creating a volume and stored in the metadata. `argon_utils.py` just receives the salt (from the header) to derive the same key when decryption is needed.

*How it works:* When a new volume is created, `argon_utils.py` is used to derive the master encryption key from the user’s password. First, a random salt is generated (via utils) and saved in the header. The password and salt are then passed to the Argon2 function, yielding (for example) a 256-bit key. That key is then used by the encryption module (`chunk_crypto`) to encrypt data. When opening an existing volume, the process is reversed: the salt is read from the header, Argon2 is applied with the user-supplied password, and the resulting key is used to attempt to decrypt the data or metadata.

*How to modify:* If developers want to switch the key derivation scheme, this is the module to change. For example, to use **scrypt** or PBKDF2 instead of Argon2, a new function could be created here or the existing one updated, remembering to adjust how parameters are handled (and store any new parameters in the metadata if needed). If you want to increase security, raising Argon2’s `t_cost` or `m_cost` will make derivation slower (improving resilience against attacks but slightly slowing volume opening for all). Maintain compatibility: old volumes derive keys with old parameters – a solution is to store the KDF algorithm ID and parameters in the metadata so `argon_utils.py` can apply the correct procedure depending on the volume version. In short, make changes here to evolve the KDF, but thoroughly test compatibility with existing volumes and password-attack resistance.

### chunk_crypto.py – Block-Based Data Encryption

The `chunk_crypto.py` module implements the low-level encryption and decryption operations that handle the actual volume data. “Chunk” refers to splitting the data into fixed-size blocks, which is useful for streaming and handling large files. Main responsibilities and how it works:

- **Cipher Initialization**: Generally, before encrypting or decrypting a block, a cipher object is created (for example, an AES object using a key and IV). `chunk_crypto.py` likely provides functions like `initialize_cipher(key, iv)` or builds this directly within encryption functions.
- **Encrypting and Decrypting Chunks**: Dedicated functions, such as `encrypt_chunk(data: bytes, key: bytes, iv: bytes) -> bytes` and `decrypt_chunk(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes`. These use the underlying crypto library to apply the symmetric cipher.
- **Operating Mode**: The chosen encryption mode affects how blocks are handled:
  - If it’s a streaming or CTR mode, each chunk may be encrypted independently using a counter or unique IV.
  - If it’s GCM (an AEAD mode), each chunk also produces an authentication tag that must be stored and verified.
  - If it’s XTS (common for disk encryption), the module may split the volume into sectors and encrypt each one with “tweaks”; however, XTS is more complex and requires two derived keys, which may be beyond a simplified implementation here.
  - **Assumption**: A simpler mode like **AES-GCM** is likely used to ensure per-chunk confidentiality and integrity. In that case, each chunk must store not only the encrypted data but also the generated authentication tag.
- **IV/Nonce Management**: For each encrypted block, it’s crucial to use a unique **IV (initialization vector)** or **nonce**. The module might define that the IV for the first block is derived from something (e.g., part of the salt or a key hash) and then increment or compute something for subsequent blocks. Another strategy is generating random IVs for each block and storing them with the encrypted data (though this increases overhead). `chunk_crypto.py` handles these details so that higher-level modules (streaming, single_shot) don’t have to worry about the low level.
- **Block Size**: Defined in `config.py` (e.g., 64 KiB). `chunk_crypto` reads this constant to know how many bytes to process at a time. Except possibly the final block of a file, which can be smaller if the total size isn’t a multiple of the block size – in that case, the encryption function must handle padding or track the actual size (e.g., using the cipher’s default padding or storing the real length somewhere).
- **Authenticity**: If no authenticated mode is used, the module could calculate an HMAC per block or globally to ensure data hasn’t been tampered with. However, this adds complexity around key management (you’d need a separate HMAC key or derive another one via Argon2). Check whether this is done in the code; if not implemented, consider future enhancements.

*How it works:* When a volume is mounted (external or hidden), after the key is derived by Argon2 (`argon_utils.py`), every read/write of encrypted data goes through `chunk_crypto`. For example, to write encrypted data: the byte stream is split into blocks of the configured size, for each block an IV is generated (perhaps by incrementing a counter), then the block is encrypted with the key and that IV. The result (and possibly the authentication tag) is written to the container file. For reading/decryption, the process is reversed: each block read from the file is taken along with (or used to compute) its corresponding IV, then decrypted with the derived key to get the original plaintext. All of this should happen transparently for higher-level modules (streaming or single_shot).

*Usage example:* A developer may directly use functions from `chunk_crypto.py` if they want to manually encrypt a block of data. A simplified example:
```python
from cryptguard import chunk_crypto, config
key = b'\x01\x02...32byteskey...'       # previously derived key
iv  = b'\x00\x00\x00\x00...16bytesiv...' # IV for this block (16 bytes for AES)
plaintext = b"Confidential data..."
ciphertext = chunk_crypto.encrypt_chunk(plaintext, key, iv)
# ... save ciphertext to a file ...
```
And for decryption:
```python
decrypted = chunk_crypto.decrypt_chunk(ciphertext, key, iv)
assert decrypted == plaintext
```
In normal CryptGuard usage via its upper layers, the developer doesn’t need to manually manage per-block IVs – this is handled internally. But to modify behavior (e.g., changing the IV generation method or implementing a new algorithm), `chunk_crypto.py` is the place.

*How to modify:* If you want to switch the encryption algorithm or operating mode, developers should change the functions in `chunk_crypto.py`. For instance, to replace AES with **ChaCha20-Poly1305**, use an appropriate crypto library and adjust the key and nonce sizes. Update `config.py` with the right constants (still 256-bit key, 96-bit nonce for ChaCha20, etc.) and ensure `metadata.py` captures any required information (like an algorithm ID to know how to decrypt). Test thoroughly to confirm volumes created with the new algorithm are recognized or that any format changes are clearly signaled to avoid decrypting with the wrong method. Another potential tweak: increase the block size to improve performance (larger blocks = fewer KDF or IV operations, but more RAM usage per block). Any changes to `chunk_crypto.py` should be accompanied by encryption/decryption tests to confirm that recovered data match the originals exactly and that incorrect passwords behave as expected (random data from a wrong password should not decrypt to anything coherent).

### metadata.py – Encrypted Volume Metadata

The `metadata.py` module defines the structure of the (header) metadata in the encrypted volume and provides functionalities to manage this structure. The metadata is crucial because it stores the information needed to derive keys and interpret the volume’s layout, both external and hidden.

Typical fields in the metadata (assuming a class like `VolumeMetadata`):

- **Identifier/Magic and Version**: A fixed value identifying the file as a CryptGuard volume and possibly a format version number. This helps validate whether the header decryption was successful (for example, you expect a specific “MAGIC” after decrypting with the password; if it doesn’t match, the password is wrong or the file is invalid).
- **Salt**: The random salt used by Argon2 to derive the key. It’s probably stored in clear text inside the *encrypted* header (i.e., within the header itself, which gets encrypted). When attempting to open the volume, the software reads the file, obtains the encrypted metadata blob, tries to decrypt it with the provided password; if successful, it extracts the salt and then applies Argon2. (Alternatively, the salt could be outside the encrypted portion so you can derive the key before decrypting the rest of the header – though a fixed, non-secret salt is not necessarily a problem. The exact strategy depends on the implementation).
- **Argon2 Parameters**: Potentially stored so you know which parameters (t_cost, m_cost, etc.) were used for the key derivation (especially useful if in future you want to support variable parameters or other KDFs). Could include t_cost, m_cost, etc., if you want to allow these values to vary by volume.
- **Volume Size**: The total size of the container file or of the external volume data space.
- **Hidden Volume Size**: If a hidden volume was created, it may store its size or offset. Some designs avoid explicitly listing the hidden volume’s size in the external header, so that an attacker with external header access won’t see that “reserved space.” In CryptGuard, that information could appear only in the hidden volume’s header, not in the external one.
- **Checksum/Signature**: In addition to the identifying magic, there may be a checksum or HMAC for the other fields to validate header integrity (with the derived key). In authenticated modes, GCM/Poly1305 on the header can ensure integrity. In any case, it’s important that any unauthorized alteration to the header be detectable (otherwise, an attacker could tamper with parameters to weaken the derivation, for example).
- **Encrypted Master Key (optional)**: In some implementations, rather than using the Argon2-derived key directly to encrypt the data, a random master key for the volume is generated and stored in the header, encrypted with the password-derived key. This allows changing the password without re-encrypting the entire volume – you just decrypt the master key with the old password and re-encrypt it with the new one. It’s unclear if CryptGuard follows this model; if not, the Argon2-derived key *is* the data key. If so, the header would hold the encrypted master key (and Argon2 only unlocks it).
- **Other Fields**: Possibly includes indicators like “has hidden volume (bool)” or padding to fill a fixed header size. However, an explicit indicator of a hidden volume could compromise plausible deniability if an attacker reads the external header and sees a “hidden volume: true” flag. Hence, the external volume header likely **does not include** any direct reference to a hidden volume. The hidden volume would have its own header stored separately (similar to the external header but perhaps without a “hidden volume” field).

*How it works:* Typically, `metadata.py` defines a class or structure plus methods for (de)serializing metadata to bytes. For example, `Metadata.to_bytes()` might produce a fixed-size binary block for the header ready to be encrypted/written, and `Metadata.from_bytes(data: bytes)` might interpret a binary block read/decrypted from the file into a Python object with accessible fields. When creating a new volume, CryptGuard builds a metadata object, fills in the fields (generates the salt, sets parameters, etc.), serializes it to bytes, and encrypts that header with the derived key before writing it at the start of the file. When opening a volume, the reverse happens: read the initial bytes of the file (the header size), try to decrypt with the user’s password-derived key; if you get coherent results (the correct `magic` field, for example), then do `Metadata.from_bytes` to load the fields and use them (e.g., hidden volume offset, Argon2 parameters, etc.).

*Usage example:* Generally `metadata.py` is used internally by the system, not directly by the end user. But a developer modifying or inspecting could do something like:
```python
from cryptguard.metadata import VolumeMetadata
meta = VolumeMetadata(
    salt=os.urandom(config.SALT_SIZE),
    has_hidden=True,
    hidden_size=1024*1024*100,  # 100 MB hidden volume
    argon_params={'t_cost': 3, 'm_cost': 2**16, 'parallelism': 4},
    version=1
)
header_bytes = meta.to_bytes()
# ... encrypt header_bytes with the derived key and write to file ...
```
And to read:
```python
# decrypt first_header_bytes with the key derived from the given password...
plaintext_header = cipher.decrypt(first_header_bytes)
meta = VolumeMetadata.from_bytes(plaintext_header)
print("Salt:", meta.salt, "Hidden volume?", meta.has_hidden)
```
Again, many exact details depend on the implementation, but the idea is that the module makes handling the header easier so other components don’t have to deal with offsets and binary structures manually.

*How to modify:* If you need to add extra info to the header (e.g., a new configuration field or support for multiple hidden volumes), this is the module to change. In doing so, be careful with fixed header size – changing fields might require either keeping the same size or bumping the format version and reading it conditionally. For instance, to add a “creation date” or “cipher algorithm used,” you could use some reserved space or expand the header if possible. Be sure to update the logic in `to_bytes`/`from_bytes` and validate the info during mounting. **Never store sensitive information in plaintext in the header** (except the non-secret salt), as the header can be exposed if an adversary has the file. Store critical data encrypted or derived so that it doesn’t reveal anything (for example, if you add a “has_hidden” field, consider encoding it indirectly or omitting it in the external volume). Also consider compatibility implications: old volumes lacking the new field should still be readable (perhaps inferring default values). In short, `metadata.py` is central to the container format definition – modify it with extra caution, since mistakes here can render volumes inaccessible.

### hidden_volume.py – Hidden Volume Management

This module implements the functionality for creating and handling hidden volumes inside a container. It orchestrates calls to other modules (metadata, chunk_crypto, argon_utils) to perform complex operations involving two sets of data (external and hidden). Key functions and behaviors in `hidden_volume.py` may include:

- **Volume Creation (Init)**: A function like `create_volume(file_path, external_password, hidden_password=None, hidden_size=0, external_data=None)`. This function creates a new encrypted container file. Typical steps:
  1. **File Preparation**: Opens a new file at `file_path` and sets its total size. If a hidden volume is requested (`hidden_password` provided and `hidden_size > 0`), the total file size must accommodate both the external volume and the hidden one. For example, if the user wants a 100 MB container with a 20 MB hidden volume, the file might be 100 MB total; the external volume can occupy up to 80 MB, and 20 MB is reserved for the hidden volume.
  2. **Initial Filling**: Writes random data across the entire file (or at least in the area allocated for the hidden volume). This ensures that even unused volume portions appear random, indistinguishable from real encrypted data. This step uses random generation functions (from utils) to produce blocks repeatedly.
  3. **External Volume Setup**: Generates an Argon2 salt, derives the external password key. Builds the external volume metadata (via `metadata.py`), possibly indicating the total space for the external volume (the total minus the hidden space). If a hidden volume is to be created, it may or may not be indicated in the external metadata; ideally, it isn’t explicitly labeled (the external volume may just be seen as smaller, offering no explanation for the unused space – to an attacker, that leftover area just looks like random free space).
  4. **Hidden Volume Creation (optional)**: If requested, similarly generate a salt and derive the key for the hidden password. Build the metadata for the hidden volume, indicating its size and possibly its position. The hidden volume position is typically allocated at the end of the container file. For example, a total size of 500 MB with a 100 MB hidden volume might start the hidden offset at 400 MB. Thus, the hidden volume’s header might be stored right at the start of that region (offset 400 MB into the file).
  5. **Writing Headers**: Encrypt and write the external volume header at the beginning of the file. If there is a hidden volume, encrypt and write its header to its designated region (for example, at the start of the hidden area or at the end of the file – some designs put the hidden header at the file’s end for greater stealth).
  6. **Initial Data**: If `external_data` were provided (the user wants to put some files into the external volume right away), the module could encrypt them and store them immediately after the external header. However, because the external volume is typically mounted later for writing, CryptGuard can simply create an empty volume (just headers and random filling). The same goes for initial hidden data – usually the hidden volume starts empty.
  
- **Volume Opening/Mounting**: A function like `open_volume(file_path, password) -> VolumeObject`. Here the module decides, based on the provided password, which volume is being accessed:
  1. Reads the encrypted external header from the file start and attempts to decrypt it with the password (deriving the key via Argon2 and decrypting).
  2. If decryption yields valid metadata (correct magic, known version, etc.), then the password corresponds to the external volume. The module returns a representation of the external volume (e.g., an object holding the derived key and its space limits). That object can be used with `streaming.py` to read/write data in the external volume.
  3. If the password fails on the external volume (metadata is invalid), the module then tries to read the hidden volume header (at the offset where it’s presumably located, like the last 512 bytes of the file or similar). It attempts to decrypt with the derived key. If it yields valid metadata, then the password is for the hidden volume. It returns an object representing the hidden volume.
  4. If neither attempt succeeds, the password is invalid or the file is not a CryptGuard container.
  
  This flow implies that `hidden_volume.py` knows where to look for the hidden volume header. This could be fixed (e.g., the last sector of the file is always the hidden header) or derived from the total size minus the header size (if we assume the hidden volume uses the file’s end, with its header at the start of that region). Another possibility is to store both headers consecutively at the front, one for the external, one for the hidden, and distinguish them by trying each password. But that would make it easy to detect two headers. Likely the design places them in separate locations for better concealment.
  
- **Data Reading/Writing**: Once it’s determined which volume (external or hidden) is active, `hidden_volume.py` coordinates I/O operations via the streaming or single_shot modules:
  - For sequential read/write, it uses `streaming.py`, passing the volume’s start position and size in the file. For example, for the external volume, that could be right after the external header until the start of the hidden space (or the entire file size if there is no hidden volume). For the hidden volume, streaming might start at the hidden region’s offset until the file’s end.
  - The module may also provide simpler methods like `read_file` or `write_file` that use streaming or single_shot internally for common file operations. Thus, a developer might directly request to extract a file from the hidden volume by specifying an external path and an internal path.
  
- **Protecting Against Overwrite**: If the external volume is mounted with knowledge of the hidden password, `hidden_volume.py` can enable protection against writing to hidden areas. That might be done by checking each external write operation to see if the offset goes beyond the allowed boundary (the start of the hidden volume). If it does, return an error or truncate. This requires the user to also supply the hidden password when mounting the external volume (indicating knowledge of the hidden volume). If not yet implemented, it’s a future improvement.

*Usage examples:* Suppose a developer wants to create an encrypted volume with a hidden volume from code (not using the CLI). They might do:
```python
from cryptguard import hidden_volume
# Create a 100 MiB volume with a 20 MiB hidden volume inside
hidden_volume.create_volume(
    "my_container.dat",
    external_password="password123",
    hidden_password="secret!",
    hidden_size=20 * 1024 * 1024
)
```

This generates `my_container.dat` at 100 MiB, with an external volume of ~80 MiB and a hidden volume of 20 MiB. Then, to write data to the hidden volume:

```python
vol = hidden_volume.open_volume("my_container.dat", password="secret!")  # opens hidden volume
# 'vol' might be an object that provides access, for example:
vol.write(b"secret message", path_in_volume="note.txt")
vol.close()
```

Or, using manual streaming:

```python
# Open hidden volume and get limits for streaming
vol = hidden_volume.open_volume("my_container.dat", password="secret!")
start, length = vol.data_offset, vol.data_size  # position and size of the hidden volume in the file
with open("my_container.dat", "rb") as container:
    container.seek(start)
    ciphertext = container.read(length)
# (Then decrypt ciphertext with vol.key using streaming.decrypt_stream or similar)
```

For the external volume:

```python
vol_ext = hidden_volume.open_volume("my_container.dat", password="password123")
# Write data to the external volume (up to 80 MiB limit, without touching hidden area)
vol_ext.write_file("document.txt", data=b"external file")
```

The exact API details vary, but essentially `hidden_volume.py` offers these higher-level operations so the rest of the application (or the CLI in `main.py`) can create and access volumes without worrying about offsets and re-deriving the key each time (that’s handled once you obtain the volume object with the ready key).

*How to modify:* Changes in this module must be handled with utmost care, as it is the core of the hidden volume logic:
- **New Features**: If you want to support multiple hidden volumes (more than one hidden volume with different passwords inside the same container), this is the module to expand. You’d have to define how to split the free space into multiple hidden areas, with multiple hidden headers. The opening logic would have to attempt multiple header positions for different passwords.
- **Allocation Strategy Changes**: By default, it may use the end of the file for the hidden volume. A developer could store the hidden volume at another position (e.g., immediately after the external header, filling the middle of the file, leaving the rest for the external volume). That would require recalculating offsets and maybe storing some indicators (which complicates plausible deniability). Any such change must still ensure that without the hidden password, the hidden area is indistinguishable from random data.
- **Hidden Volume Protection**: Implementing the functionality to protect the hidden volume from overwrite when the external is mounted. This might prompt for both passwords at once and mark the external volume object with a protected limit. Then, during each write operation, check that limit. Introducing this feature improves security when volumes are in active use and can be added here.
- **Performance**: If you need to enhance performance when accessing volumes, you could introduce key caching (if Argon2 is very slow, you might store the derived key in memory during prolonged use, though always deriving the key at each open is safer so you’re not holding it in RAM too long). You might also optimize random data generation for large file creation using bigger blocks or multiple threads.  
- **Secure Clearing**: When closing a volume, it might be prudent to clear (zero out) any memory buffers holding keys or passwords. Check if the module already does this; if not, consider adding it to avoid leaving sensitive data in variables.

In short, `hidden_volume.py` coordinates high-level operations involving two encrypted data sets in the same file. Any new hidden-volume-related features or changes go here. Thorough testing is key: create volumes, open them with correct and incorrect passwords, verify the hidden volume remains undetectable, and ensure no data is leaked (e.g., differences in response time if a hidden volume exists).  

### streaming.py – Streaming Encryption

`streaming.py` is responsible for reading and writing encrypted data in a continuous flow (stream), instead of loading it all in memory. This module is useful for working with large files or integrating CryptGuard into data pipelines (e.g., encrypting data as it’s transmitted). Main elements:

- **Stream Interface**: May define classes or generator functions. For example, an `EncryptedWriter` class that, when given an output file and key, offers a `write(plaintext_chunk)` method that automatically encrypts and writes to the file. Similarly, an `EncryptedReader` that, given an encrypted file and a key, provides a `read()` that returns decrypted plaintext chunks.
- **Use of chunk_crypto**: Internally, streaming.py uses the functions in `chunk_crypto.py`. It manages chunk-by-chunk iteration:
  - Reads X bytes from the encrypted file, calls `decrypt_chunk` and yields them to the consumer.
  - Or receives X bytes of plaintext from the producer, calls `encrypt_chunk` and writes them to the output file.
- **State Management**: If the cipher mode requires maintaining state between blocks (e.g., CTR mode incrementing a counter, or GCM context if splitting messages), the implementation might keep that context. Often, however, `chunk_crypto.py` was designed for independent blocks with computable IVs, so `streaming.py` can simply loop, using the block index to generate the IV or retrieving it from the file if stored.
- **Buffering and Block Size**: streaming likely reads/writes the encrypted file in blocks of the configured size (e.g., 64 KB). It might use an internal buffer for partial blocks (like the final block if the file doesn’t align).
- **High-Level API**: In addition to these classes, it may offer functions like `encrypt_stream(input_file, output_file, key)` and `decrypt_stream(input_file, output_file, key)` that read from the input file and write to the output file entirely. This hides the loop of reading and writing in chunks, making usage simpler.
- **I/O Considerations**: It ensures that files are opened in the correct binary mode, handles read/write exceptions (e.g., running out of disk space), and closes the files. It might provide progress output (not mandatory, but helpful for large volumes; could be unimplemented for simplicity, but feasible to add).

*How it works:* Suppose we have `encrypt_stream`. A possible flow:
```python
from cryptguard import streaming, chunk_crypto, argon_utils, metadata

# Prepared parameters: input and output files, and user-supplied password
with open("plaintext_file.bin", "rb") as f_in, open("encrypted_file.bin", "wb") as f_out:
    # Derive the key (normally done earlier and stored in metadata,
    # but if we want to use streaming by itself:)
    key = argon_utils.derive_key(password="my_password", salt=my_salt)
    streaming.encrypt_stream(f_in, f_out, key)
# encrypted_file.bin now contains the data, block by block, encrypted
```
Within `encrypt_stream`, the code might do something like:
```python
def encrypt_stream(f_in, f_out, key):
    chunk_size = config.CHUNK_SIZE
    iv = initialize_iv()  # define IV for the first block
    block_idx = 0
    while True:
        data = f_in.read(chunk_size)
        if not data:
            break
        # if data is smaller than chunk_size, handle padding or store actual size
        encrypted = chunk_crypto.encrypt_chunk(data, key, iv_for_index(block_idx))
        f_out.write(encrypted)
        block_idx += 1
```
Where `iv_for_index` might be in chunk_crypto or computed inside streaming: if the initial IV is set (e.g., all zeros or derived) and we increment block_idx (for CTR/GCM, that may be appended with a counter, for XTS we might do a tweak, etc.). Similar for `decrypt_stream`:

```python
with open("encrypted_file.bin", "rb") as f_in, open("decrypted_file.bin", "wb") as f_out:
    key = argon_utils.derive_key(password="my_password", salt=my_salt)
    streaming.decrypt_stream(f_in, f_out, key)
```
Where `decrypt_stream` reads as it was written:
```python
def decrypt_stream(f_in, f_out, key):
    chunk_size_encrypted = config.CHUNK_SIZE_on_disk  # maybe chunk_size + tag if GCM
    block_idx = 0
    while True:
        encrypted = f_in.read(chunk_size_encrypted)
        if not encrypted:
            break
        plain = chunk_crypto.decrypt_chunk(encrypted, key, iv_for_index(block_idx))
        f_out.write(plain)
        block_idx += 1
```
Note: If an authenticated mode (GCM) is used, `chunk_crypto` might handle tag verification inside `decrypt_chunk` and throw an exception if invalid (indicating data corruption or wrong password). Streaming should stop and report the error accordingly.

*How to modify:* Generally, there’s no need to change `streaming.py` unless:
- You’re changing how IVs are managed (e.g., switching from AES-GCM to AES-CBC, where the next block’s IV must be the last block’s ciphertext).
- You want to support **resumable** encryption or random access: e.g., implementing partial reads from a specific offset. Then you might add something like `decrypt_chunk_at(file, key, index)` within streaming logic.  
- Adding **progress feedback**: if integrating with a UI/CLI, you might want to print how many bytes have been processed periodically.
- **Compression**: Not originally the module’s function, but you could compress data before encrypting to reduce size, implemented here (or in single_shot) before chunk_crypto calls.
- **Parallelism**: to speed things up on multicore machines, you might process multiple chunks in parallel. This is complex in Python due to the GIL for CPU-bound tasks; you might use multiprocessing or chunk-based concurrency. It’s a major change requiring careful synchronization and testing.

Unless necessary, it’s typically safe not to modify streaming; developers mostly interact with this module for usage. If you find bugs in read/write logic (like final block padding), then fix them here.

### single_shot.py – One-Shot Operations

`single_shot.py` provides convenience functions to encrypt or decrypt data in one go, i.e., loading everything into memory instead of streaming. While not efficient for very large files, it’s useful for simple use cases or testing.

Likely functions include:
- `encrypt_file(input_path, output_path, password)` – opens an entire file, reads its entire contents into memory, derives the key, encrypts all data (possibly still in chunks, or all at once), and saves to the output.
- `decrypt_file(input_path, output_path, password)` – the same, but for decryption.
- Possibly `encrypt_data(data_bytes, password) -> bytes` and `decrypt_data(data_bytes, password) -> bytes` – for direct programmatic use with in-memory data, no file I/O.

*How it works:* This module is mostly a simple facade. Internally, it reuses existing components:
- For key derivation, it calls `argon_utils.derive_key`.
- For data encryption, it may either call `chunk_crypto.encrypt_chunk` if the entire data fits in one chunk or handle multiple chunks if it’s large. But if we’re chunking, it’s almost the same as streaming – we can do it here or delegate to streaming.  
- Another approach is that single_shot sets the chunk size to the data length, effectively encrypting it all in one block (managing any overhead).
- After obtaining the ciphertext, it writes it directly to output (or returns it if it’s a *data* function).
- Similarly for decryption: read the file contents, decrypt all at once, get plaintext, save or return it.

*Usage example:*  
```python
from cryptguard import single_shot

# Encrypt a file simply
single_shot.encrypt_file("secret.txt", "secret.cgd", password="my_password")

# Decrypt
single_shot.decrypt_file("secret.cgd", "secret_decrypted.txt", password="my_password")

# Or encrypt data in memory
cipher_bytes = single_shot.encrypt_data(b"in-memory text", password="1234")
plain_bytes = single_shot.decrypt_data(cipher_bytes, password="1234")
```
Here, `"secret.cgd"` is the encrypted output file (could have a custom extension, `.cgd` is just illustrative). Note that this simple interface doesn’t handle hidden volumes – it might just be straightforward file encryption using a password. It’s useful when the user doesn’t need a hidden volume and just wants a quick encryption method.

*How to modify:* This module is straightforward:
- You might adapt it to handle hidden volumes if desired, for example a function `create_hidden_file(container_path, outer_password, hidden_password, outer_data, hidden_data)` that places two buffers into the container. But that could replicate `hidden_volume` logic, so it might not be necessary.
- You could make it accept file-like objects instead of paths.
- Improve memory usage: if the file is huge, reading it all into memory could be problematic. One could adapt it internally to use streaming so memory doesn’t blow up, though that contradicts the “single-shot” name. You might do it “under the hood,” though, for user convenience.
- If chunk logic changes (e.g., new tags or metadata), ensure single_shot remains consistent with streaming and hidden_volume so they produce the same results for the same input. Testing should confirm equivalence.
- Otherwise, you can leave this module alone. Many modifications here would simply be calling the other modules, so keep it up to date if `argon_utils` or `chunk_crypto` signatures change.

### main.py – CLI and Initialization

`main.py` is the script that brings everything together and provides the user interface (normally via command line). It parses arguments, calls the appropriate module functions, and handles basic user input/output.

Possible functionalities in `main.py`:

- **Argument Parsing (CLI)**: Likely uses `argparse` (or similar) to define options and commands. Example commands:
  - `cryptguard create -o <container_file> -p <external_password> [-P <hidden_password> -s <hidden_size>]` – creates a new volume, requiring the external password and optionally the hidden password/size.
  - `cryptguard open -o <container_file> -p <password> -d <destination_dir>` – opens a volume (external or hidden depending on the password) and **extracts** its contents to a destination directory (if CryptGuard supports multiple files or if it treats the volume as a virtual disk).
  - `cryptguard encrypt -i <input_file> -o <output_file> -p <password>` – simple file encryption mode (no hidden volume, using single_shot or streaming).
  - `cryptguard decrypt -i <encrypted_input_file> -o <output_file>` – decrypt a simple file (the password is prompted or passed via an argument).
  
  The above names are hypothetical, but illustrate how `main.py` might structure subcommands for different uses (creating volumes, simple file encryption, etc.). It would also handle options like verbose mode, help, and version.
- **User Interaction**: For passwords, it’s important not to pass them plainly through CLI options (risk in shell history or process listing). `main.py` could use `getpass.getpass()` to prompt for the password discreetly. Even if `-p` is provided, if left empty, the program could prompt interactively.
- **Module Calls**: After parsing, `main.py` calls the internal modules:
  - If the command is `create`: calls `hidden_volume.create_volume` with the parsed parameters. May also build the external volume’s initial content if the user passed something in.
  - If the command is `encrypt`: decides whether to use `single_shot.encrypt_file` (if the file is small or for simplicity) or `streaming.encrypt_stream` (for large files). Could be a manual or automatic decision based on file size.
  - If the command is `open` or `decrypt`: for volumes, calls `hidden_volume.open_volume` then uses `streaming` to extract data or something similar; for a simple file, calls `single_shot.decrypt_file`.
  - If there’s a command like `add-hidden` (to add a hidden volume to an existing container), `main.py` might open the volume externally with both passwords and then call something to create the hidden portion (not sure if that’s supported, but it’s possible).
- **Messages and Error Handling**: `main.py` provides feedback in the console, for example:
  - Success messages after creating a volume (and usage instructions).
  - Clear error messages for incorrect passwords when opening a volume.
  - Warnings if trying to create a hidden volume larger than the external volume, etc.
  - Help displayed if using invalid options.
- **Initialization**: Possibly imports all modules and sets up something global (though not necessarily). It might define basic logging or check if certain dependencies (e.g., argon2 library) are available.
- **Execution Mode**: Typically something like:
  ```python
  if __name__ == "__main__":
      main()
  ```
  so running `python main.py ...` works directly. The `main()` function internally configures argparse subcommands and routes them to the right functions.

*CLI usage example:*  
In a terminal, a developer or end user might do:
```
# Create a 100 MB container with 20 MB hidden
$ python cryptguard/main.py create -o mycontainer.cgd --password-ext "password123" --password-hidden "secret!" --hidden-size 20
Encrypted volume created successfully: mycontainer.cgd (20 MB hidden volume included).

# Store a file in the hidden volume:
$ python cryptguard/main.py open -o mycontainer.cgd --password "secret!"
... (mounts hidden volume in extraction mode) ...
Copying files from hidden volume to ./hidden_volume_out/
```
Perhaps CryptGuard doesn’t implement a full file system; if so, the `open` command might simply decrypt the entire volume to an output file if it assumes a single data stream. Alternatively, if it sees the container as a drive, you could integrate with a FUSE-based mount, but that’s beyond the current scope. The example above just assumes a simple extraction approach.

*How to modify:* Developers can extend `main.py` to add new commands or adjust usage:
- **New Subcommands**: For instance, `change-password` to change the volume’s password. This would involve reading the volume with the old password, re-encrypting the header with the new password, and saving. That logic involves `hidden_volume` and `metadata`, but is exposed here.
- **GUI Integration**: If you plan on a graphical interface, `main.py` might be adapted to skip argparse and still serve as an entry point. Or you keep it strictly for CLI, while the GUI calls the modules directly.  
- **Usability Enhancements**: For example, let the user omit `--hidden-size` and automatically derive it from the file size, or have a command to display volume info (not the content, but size, etc.).  
- **Detailed Logging**: Add a debug option (`-v` or `--verbose`) to print internal steps (“Deriving key with Argon2...,” “Creating external volume header...,” etc.). Use Python’s logging module. Be sure not to log sensitive info (like raw passwords or keys).  
- **Input Validation**: Check that the hidden size isn’t larger than the total volume, that the password isn’t empty, etc., returning clear error messages.

Overall, `main.py` is the “glue” that ties everything together. Modifying it is relatively safe (it doesn’t affect core cryptography) as long as the internal logic of the modules is called correctly. Still, test any new command flow to ensure no unsupported scenarios (e.g., using the hidden password with the wrong command) are introduced.

## Final Considerations

CryptGuard provides a solid foundation for volume encryption with concealment, but like any security project, it requires careful maintenance and potential future improvements:

- **Testing and Verification**: Strongly recommended to implement unit and integration tests for all modules. Tests should cover: volume creation (verify correct size, inability to mount hidden volume without the right password), file encryption/decryption (ensure original content is recovered bit for bit), error handling (wrong password shouldn’t crash the program, but produce a clear error), and edge cases (hidden volume of zero size, same password for external and hidden, very large files, etc.). Before releasing modifications, validate against this test suite to confirm security isn’t compromised.
- **Security Enhancements**: Consider adding layers of security:
  - *Data Authenticity*: If not already implemented, include a global volume integrity check to detect tampering. One approach is storing an HMAC of the entire volume (or sections) using a derived key. However, that might reveal there’s more than one volume if the hidden part is included. Another option is always using an authenticated cipher (AES-GCM) for each chunk, ensuring local integrity.
  - *Memory Protection*: Ensure passwords and keys are cleared from memory as soon as possible. Python doesn’t allow fine-grained memory control, but best practices include overwriting variables and using immutable byte objects carefully. Review points where sensitive data reside in memory and reduce their exposure (e.g., after deriving a key, don’t keep the plaintext password around).
  - *Random Numbers*: Confirm all random sources are cryptographically secure (e.g., `os.urandom` or `secrets`). Avoid Python’s `random` for cryptographic purposes.
- **Documentation and Usability**: Update user documentation as new features are added. For instance, if you implement password changing or hidden volume protection, explain how in the user README. From the developer perspective, keep code comments that clarify critical parts (key derivation, metadata structure, etc.). This aids future contributors.
- **Compatibility and Migration**: If the project evolves to new versions (v2, v3 of the format), plan a versioning and migration scheme. The metadata version field can help the code recognize older volumes and migrate them (e.g., decrypt with the old method and rewrite the header in the new format). At least maintain the ability to read old formats, or provide a conversion tool.
- **New Features**: Potential expansions might include:
  - Support for **different encryption algorithms** (AES, ChaCha20, Twofish, etc.), selectable at volume creation. This attracts users with specific needs and offers redundancy if one algorithm is compromised.
  - **Transparent compression** before encryption to save space, optionally enabled.
  - **Logical drive mounting**: Integrate with FUSE (on Unix systems) or other APIs to allow CryptGuard’s container to appear as a drive, letting users manage files and folders normally inside the volume. This is a significant project on its own, akin to TrueCrypt/VeraCrypt’s approach.
  - **Graphical interface**: Create a user-friendly GUI that uses the internal modules. The modular design helps here, since the core logic is separate from the CLI.
- **Good Maintenance Practices**: When modifying code:
  - Follow a consistent style (PEP 8 for Python). Use clear, descriptive names, especially in security-critical contexts.
  - Have at least two developers do **code reviews** for security-related changes if possible. Cryptographic bugs can be subtle and have big consequences.
  - Increment new features gradually, testing each in isolation (e.g., if changing an algorithm, first do a manual test to ensure the data matches).
  - Keep dependencies (like crypto libraries) up to date for security patches, monitoring API changes.  
  - Document key design decisions or trade-offs in this developer README so future maintainers understand why certain choices were made (e.g., “We do not store a hidden flag in the external header to preserve plausible deniability.”).

In conclusion, CryptGuard is architected with clear separation of responsibilities, which should ease developers’ work in navigating and modifying the code. The hidden volume implementation adds interesting complexity, but with the explanation above, it should be clearer where each piece fits. Happy coding!
