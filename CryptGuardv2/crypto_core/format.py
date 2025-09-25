"""
Especificação do formato de arquivo CG2 (CryptGuard v2)
"""

import json
import struct
from typing import Any, Dict

class InvalidHeaderError(ValueError):
    """Indica que o header do arquivo está malformado ou não é suportado."""
    pass

MAGIC = b"CG2\x00"
CURRENT_VERSION = 3
ALGORITHMS = {"xchacha20poly1305_ietf": 1}
KDFS = {"argon2id": 1, "argon2id_hkdf": 2}
HEADER_SIZE = 256
LEGACY_HEADER_SIZE = 64

def _validate_header_fields(params: Dict[str, Any]) -> None:
    required_fields = ["version", "algorithm", "kdf", "salt_kdf", "hkdf_salt"]
    if not all(field in params for field in required_fields):
        raise InvalidHeaderError("Header JSON não contém todos os campos obrigatórios.")
    if params["version"] != CURRENT_VERSION:
        raise InvalidHeaderError(f"Versão de header não suportada: {params['version']}")

def serialize_header(params: Dict[str, Any]) -> bytes:
    _validate_header_fields(params)
    header_json = json.dumps(params, separators=(",", ":")).encode("utf-8")
    if len(header_json) > HEADER_SIZE:
        raise InvalidHeaderError(f"Header serializado é muito grande: {len(header_bytes)} > {HEADER_SIZE}")
    return header_json.ljust(HEADER_SIZE, b"\x00")

def _parse_header_json(header_bytes: bytes) -> Dict[str, Any]:
    try:
        header_json_str = header_bytes.rstrip(b"\x00").decode("utf-8")
        if not header_json_str:
            raise json.JSONDecodeError("Header vazio após strip", "", 0)
        params = json.loads(header_json_str)
        _validate_header_fields(params)
        return params
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise InvalidHeaderError(f"Falha ao decodificar header JSON: {e}") from e
    except InvalidHeaderError:
        raise # Re-levanta a exceção de validação
    except Exception as e:
        raise InvalidHeaderError(f"Erro inesperado ao processar o header: {e}") from e

def deserialize_header(header_bytes: bytes) -> Dict[str, Any]:
    """Deserializa header, com fallback para o formato legado."""
    if not header_bytes:
        raise InvalidHeaderError("Header não pode ser vazio.")
    try:
        # Tenta como header moderno
        return _parse_header_json(header_bytes)
    except InvalidHeaderError as modern_error:
        # Se falhar e o tamanho for de um header legado, tenta o fallback
        if len(header_bytes) == LEGACY_HEADER_SIZE:
            try:
                # Re-parse, mas qualquer erro aqui é final
                return _parse_header_json(header_bytes)
            except InvalidHeaderError as legacy_error:
                 # Lança o erro do legado, que é mais relevante
                 raise legacy_error from modern_error
        # Se não for do tamanho legado, o erro original é o correto
        raise modern_error

def get_aad_for_header(header_bytes: bytes) -> bytes:
    if len(header_bytes) != HEADER_SIZE:
        raise ValueError(f"Header para AAD deve ter exatamente {HEADER_SIZE} bytes")
    return header_bytes

def create_default_params() -> Dict[str, Any]:
    from .kdf_params import generate_salt, get_cached_params
    return {
        "version": CURRENT_VERSION,
        "algorithm": ALGORITHMS["xchacha20poly1305_ietf"],
        "kdf": KDFS["argon2id_hkdf"],
        "salt_kdf": generate_salt().hex(),
        "hkdf_salt": generate_salt().hex(),
        "argon2_params": get_cached_params(),
    }