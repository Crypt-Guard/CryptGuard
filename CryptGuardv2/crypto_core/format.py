"""
Especificação do formato de arquivo CG2 (CryptGuard v2)

Layout binário do header e convenções para AAD (Associated Data).
Usado para interoperabilidade e documentação.
"""

import json
import struct
from typing import Any

# Magic bytes (4 bytes) - identifica arquivos CG2
MAGIC = b"CG2\x00"

# Versão atual do formato
CURRENT_VERSION = 3

# Algoritmos suportados
ALGORITHMS = {
    "xchacha20poly1305_ietf": 1,
}

# KDFs suportados
KDFS = {
    "argon2id": 1,
    "argon2id_hkdf": 2,  # Argon2id + HKDF para sub-chaves
}

# Tamanhos em bytes
HEADER_SIZE = 256  # Tamanho fixo do header (ajustado para acomodar parâmetros)
LEGACY_HEADER_SIZE = 64  # Tamanho do header antigo para compatibilidade


def serialize_header(params: dict[str, Any]) -> bytes:
    """
    Serializa parâmetros do header para bytes.

    Args:
        params: Dicionário com parâmetros de criptografia

    Returns:
        Bytes do header serializado

    Raises:
        ValueError: Se parâmetros inválidos
    """
    # Valida campos obrigatórios
    required_fields = ["version", "algorithm", "kdf", "salt_kdf", "hkdf_salt"]
    for field in required_fields:
        if field not in params:
            raise ValueError(f"Campo obrigatório ausente: {field}")

    # Valida valores
    if params["version"] != CURRENT_VERSION:
        raise ValueError(f"Versão não suportada: {params['version']}")

    if params["algorithm"] not in ALGORITHMS.values():
        raise ValueError(f"Algoritmo não suportado: {params['algorithm']}")

    if params["kdf"] not in KDFS.values():
        raise ValueError(f"KDF não suportado: {params['kdf']}")

    # Serializa como JSON compacto
    header_json = json.dumps(params, separators=(",", ":"))

    # Converte para bytes
    header_bytes = header_json.encode("utf-8")

    if len(header_bytes) > HEADER_SIZE:
        raise ValueError(f"Header muito grande: {len(header_bytes)} > {HEADER_SIZE}")

    # Preenche com zeros para tamanho fixo
    header_bytes = header_bytes.ljust(HEADER_SIZE, b"\x00")

    return header_bytes


def deserialize_header(header_bytes: bytes) -> dict[str, Any]:
    """
    Deserializa header de bytes com retrocompatibilidade.

    Tenta primeiro 256B, depois 64B (legado), remove padding NUL e parse JSON.

    Args:
        header_bytes: Bytes do header (HEADER_SIZE ou LEGACY_HEADER_SIZE bytes)

    Returns:
        Dicionário com parâmetros

    Raises:
        ValueError: Se header inválido
    """
    # Tenta primeiro 256B (padrão atual)
    if len(header_bytes) == HEADER_SIZE:
        try:
            return _parse_header_json(header_bytes)
        except Exception:
            pass  # Tenta 64B se falhar

    # Tenta 64B (legado)
    if len(header_bytes) == LEGACY_HEADER_SIZE:
        try:
            return _parse_header_json(header_bytes)
        except Exception:
            pass  # Fallback para tentar remover padding manualmente

    # Fallback: tenta remover padding NUL de qualquer tamanho
    try:
        return _parse_header_json(header_bytes)
    except Exception as e:
        raise ValueError(f"Header inválido: {e}") from e


def _parse_header_json(header_bytes: bytes) -> dict[str, Any]:
    """
    Parse JSON do header removendo padding NUL.

    Args:
        header_bytes: Bytes do header

    Returns:
        Parâmetros parseados

    Raises:
        ValueError: Se JSON inválido
    """
    # Remove padding NUL
    header_json = header_bytes.rstrip(b"\x00").decode("utf-8")

    # Deserializa JSON
    params = json.loads(header_json)

    # Valida campos obrigatórios
    required_fields = ["version", "algorithm", "kdf", "salt_kdf", "hkdf_salt"]
    for field in required_fields:
        if field not in params:
            raise ValueError(f"Campo obrigatório ausente: {field}")

    return params


def get_aad_for_header(header_bytes: bytes) -> bytes:
    """
    Retorna AAD (Associated Data) para um header.

    AAD = header serializado (autenticado mas não criptografado).
    Para compatibilidade, usa o header completo de 256 bytes como está no arquivo.

    Args:
        header_bytes: Bytes do header (exatamente 256 bytes)

    Returns:
        AAD para uso em AEAD
    """
    # Para compatibilidade, usa exatamente os 256 bytes do header como estão no arquivo
    # Isso garante que AAD seja consistente e inclua todo o padding se presente
    if len(header_bytes) != 256:
        raise ValueError(f"Header deve ter exatamente 256 bytes, não {len(header_bytes)}")
    return header_bytes


def get_aad_for_stream(header_bytes: bytes, block_counter: int) -> bytes:
    """
    Retorna AAD para bloco de streaming.

    AAD inclui header + contador do bloco.

    Args:
        header_bytes: Header do arquivo
        block_counter: Contador do bloco (0, 1, 2, ...)

    Returns:
        AAD para o bloco
    """
    counter_bytes = struct.pack(">Q", block_counter)  # 8 bytes big-endian
    return header_bytes + counter_bytes


def create_default_params() -> dict[str, Any]:
    """
    Cria parâmetros padrão para novo arquivo CG2.

    Returns:
        Dicionário com parâmetros padrão
    """
    from .kdf_params import generate_salt, get_cached_params

    return {
        "version": CURRENT_VERSION,
        "algorithm": ALGORITHMS["xchacha20poly1305_ietf"],
        "kdf": KDFS["argon2id_hkdf"],
        "salt_kdf": generate_salt().hex(),  # Como string hex para JSON
        "hkdf_salt": generate_salt().hex(),
        "argon2_params": get_cached_params(),
    }


def validate_params(params: dict[str, Any]) -> bool:
    """
    Valida parâmetros de criptografia.

    Args:
        params: Parâmetros a validar

    Returns:
        True se válido

    Raises:
        ValueError: Se inválido
    """
    # Versão
    if params.get("version") != CURRENT_VERSION:
        raise ValueError(f"Versão incorreta: {params.get('version')} != {CURRENT_VERSION}")

    # Algoritmo
    if params.get("algorithm") != ALGORITHMS["xchacha20poly1305_ietf"]:
        raise ValueError(f"Algoritmo incorreto: {params.get('algorithm')}")

    # KDF
    if params.get("kdf") not in KDFS.values():
        raise ValueError(f"KDF incorreto: {params.get('kdf')}")

    # Salts (devem ser hex strings válidos)
    for salt_field in ["salt_kdf", "hkdf_salt"]:
        salt_hex = params.get(salt_field)
        if not salt_hex or not isinstance(salt_hex, str):
            raise ValueError(f"Salt inválido: {salt_field}")

        try:
            bytes.fromhex(salt_hex)
        except ValueError as exc:
            raise ValueError(f"Salt hex inválido: {salt_field}") from exc

    # Parâmetros Argon2 (se presentes)
    if "argon2_params" in params:
        argon_params = params["argon2_params"]
        required_keys = ["time_cost", "memory_cost", "parallelism"]

        for key in required_keys:
            if key not in argon_params:
                raise ValueError(f"Parâmetro Argon2 ausente: {key}")

            value = argon_params[key]
            if not isinstance(value, int) or value <= 0:
                raise ValueError(f"Parâmetro Argon2 inválido: {key} = {value}")

    return True
