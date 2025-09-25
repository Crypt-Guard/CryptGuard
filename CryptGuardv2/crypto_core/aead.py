"""
Módulo centralizado para AEAD (Authenticated Encryption with Associated Data)

Implementação única usando XChaCha20-Poly1305 IETF via PyNaCl.
Usado para criptografia de arquivos CG2 e outros artefatos sensíveis.
"""

from nacl.utils import random


def encrypt_bytes(plaintext: bytes, key: bytes, aad: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Criptografa plaintext com chave e AAD usando XChaCha20-Poly1305 IETF.

    Args:
        plaintext: Dados a serem criptografados
        key: Chave de 32 bytes (256 bits)
        aad: Associated Data (não criptografado, mas autenticado)

    Returns:
        Tuple[nonce, ciphertext, tag] onde:
        - nonce: 24 bytes aleatório (XChaCha20-Poly1305 nonce)
        - ciphertext: Dados criptografados
        - tag: MAC de autenticação (16 bytes, incluído no ciphertext)

    Raises:
        ValueError: Se parâmetros inválidos
    """
    if len(key) != 32:
        raise ValueError(f"Chave deve ter 32 bytes, não {len(key)}")

    if not plaintext:
        raise ValueError("Plaintext não pode ser vazio")

    # XChaCha20-Poly1305 usa nonce de 24 bytes
    nonce = random(24)

    # Criptografa (inclui autenticação do AAD)
    # Para AEAD com AAD, usamos a API de baixo nível do PyNaCl
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

    # XChaCha20-Poly1305 IETF requer: mensagem, aad, nonce, chave
    # Retorna: ciphertext + tag (sem nonce)
    encrypted_data = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)

    # Extrai ciphertext e tag
    # O formato retornado é: ciphertext + tag (16 bytes)
    actual_nonce = nonce  # Já temos o nonce
    actual_ciphertext = encrypted_data[:-16]  # Remove tag do final
    tag = encrypted_data[-16:]  # Últimos 16 bytes são a tag

    return actual_nonce, actual_ciphertext, tag


def encrypt_bytes_with_nonce(
    plaintext: bytes, key: bytes, aad: bytes, nonce: bytes
) -> tuple[bytes, bytes, bytes]:
    """
    Criptografa plaintext com chave, AAD e nonce específico (para testes).

    Args:
        plaintext: Dados a serem criptografados
        key: Chave de 32 bytes (256 bits)
        aad: Associated Data (não criptografado, mas autenticado)
        nonce: Nonce de 24 bytes específico

    Returns:
        Tuple[nonce, ciphertext, tag] onde:
        - nonce: O nonce fornecido (24 bytes)
        - ciphertext: Dados criptografados
        - tag: MAC de autenticação (16 bytes)

    Raises:
        ValueError: Se parâmetros inválidos
    """
    if len(key) != 32:
        raise ValueError(f"Chave deve ter 32 bytes, não {len(key)}")

    if len(nonce) != 24:
        raise ValueError(f"Nonce deve ter 24 bytes, não {len(nonce)}")

    if not plaintext:
        raise ValueError("Plaintext não pode ser vazio")

    # Criptografa (inclui autenticação do AAD)
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

    encrypted_data = crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)

    # Extrai ciphertext e tag
    actual_ciphertext = encrypted_data[:-16]
    tag = encrypted_data[-16:]

    return nonce, actual_ciphertext, tag


def decrypt_bytes(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes, aad: bytes) -> bytes:
    """
    Descriptografa ciphertext com chave e AAD usando XChaCha20-Poly1305 IETF.

    Args:
        nonce: Nonce de 24 bytes usado na criptografia
        ciphertext: Dados criptografados
        tag: Tag de autenticação (16 bytes)
        key: Chave de 32 bytes
        aad: Associated Data usado na criptografia

    Returns:
        Plaintext descriptografado

    Raises:
        ValueError: Se parâmetros inválidos
        nacl.exceptions.CryptoError: Se descriptografia falha (tag inválida, etc.)
    """
    if len(key) != 32:
        raise ValueError(f"Chave deve ter 32 bytes, não {len(key)}")

    if len(nonce) != 24:
        raise ValueError(f"Nonce deve ter 24 bytes, não {len(nonce)}")

    if len(tag) != 16:
        raise ValueError(f"Tag deve ter 16 bytes, não {len(tag)}")

    if not ciphertext:
        raise ValueError("Ciphertext não pode ser vazio")

    # Reconstrói o formato esperado pelo PyNaCl
    # encrypted_data deve ser apenas ciphertext + tag (sem nonce)
    encrypted_data = ciphertext + tag

    # Descriptografa usando API de baixo nível
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt

    plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(encrypted_data, aad, nonce, key)

    return plaintext


def derive_stream_nonce(base_nonce: bytes, counter: int) -> bytes:
    """
    Deriva nonce para streaming: blake2b(base_nonce || counter)[:24]

    Usado para criptografia de arquivos grandes em blocos independentes.

    Args:
        base_nonce: Nonce base de 24 bytes
        counter: Contador do bloco (0, 1, 2, ...)

    Returns:
        Nonce derivado de 24 bytes
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if len(base_nonce) != 24:
        raise ValueError(f"Base nonce deve ter 24 bytes, não {len(base_nonce)}")

    # Deriva usando HKDF para consistência
    info = f"stream-block-{counter}".encode()
    hkdf = HKDF(
        algorithm=hashes.BLAKE2b(64),
        length=24,
        salt=None,
        info=info,
    )

    return hkdf.derive(base_nonce)


# Constantes
DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KiB por bloco
NONCE_SIZE = 24  # XChaCha20-Poly1305 nonce
TAG_SIZE = 16  # Poly1305 tag
KEY_SIZE = 32  # 256 bits
