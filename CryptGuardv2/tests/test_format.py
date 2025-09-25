import sys
import os
import pytest
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_core.format import (
    deserialize_header,
    serialize_header,
    create_default_params,
    HEADER_SIZE,
    LEGACY_HEADER_SIZE,
    InvalidHeaderError
)

def test_deserialize_fails_fast_on_malformed_modern_header():
    """Verifica que um header moderno (256b) malformado falha rapidamente."""
    malformed_json_str = '{"version": 3,,}'
    malformed_header = malformed_json_str.encode('utf-8').ljust(HEADER_SIZE, b'\x00')

    with pytest.raises(InvalidHeaderError, match="Falha ao decodificar header JSON"):
        deserialize_header(malformed_header)

def test_deserialize_handles_legacy_header_correctly():
    """Verifica que um header legado (64b) válido é deserializado corretamente."""
    params = create_default_params()
    # Simula um header legado, serializando e truncando para 64 bytes
    # Na prática, o JSON seria mais simples, mas a lógica é a mesma.
    serialized_params = json.dumps(params).encode('utf-8')
    legacy_header = serialized_params.ljust(LEGACY_HEADER_SIZE, b'\x00')

    deserialized = deserialize_header(legacy_header)
    assert deserialized == params

def test_deserialize_fails_on_malformed_legacy_header():
    """Verifica que um header legado (64b) malformado também falha."""
    malformed_json_str = '{"version": 3,,}'
    malformed_header = malformed_json_str.encode('utf-8').ljust(LEGACY_HEADER_SIZE, b'\x00')

    with pytest.raises(InvalidHeaderError, match="Falha ao decodificar header JSON"):
        deserialize_header(malformed_header)

def test_deserialize_prefers_modern_over_legacy():
    """
    Verifica que se um header de 256b for passado, ele não tenta o fallback para 64b
    se o erro não for de JSON. Ex: campo faltando.
    """
    params = create_default_params()
    params.pop("kdf") # Remove campo obrigatório

    # Este header é JSON válido, mas logicamente inválido.
    # O erro deve ser sobre o campo faltando, não sobre um fallback.
    header_bytes = json.dumps(params).encode('utf-8').ljust(HEADER_SIZE, b'\x00')

    with pytest.raises(InvalidHeaderError, match="Header JSON não contém todos os campos obrigatórios"):
        deserialize_header(header_bytes)