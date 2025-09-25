import sys
import os
import pytest

# Adiciona o diretório raiz do projeto ao sys.path para permitir imports diretos
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_core.kdf_params import derive_key_and_params, FALLBACK_ARGON2_PARAMS

def test_rejects_insecure_argon2_params():
    """
    Verifica se derive_key_and_params rejeita parâmetros Argon2id fracos
    e retorna os parâmetros de fallback seguros.
    """
    password = b"test_password"
    salt = os.urandom(16)

    # Parâmetros intencionalmente fracos, abaixo do mínimo recomendado
    weak_params = {
        "time_cost": 1,
        "memory_cost": 1024,  # 1 MiB, muito baixo
        "parallelism": 1,
    }

    # Chama a função com os parâmetros fracos
    # Espera-se um UserWarning porque os parâmetros são inseguros
    with pytest.warns(UserWarning, match="Os parâmetros Argon2id fornecidos são inseguros"):
        _, returned_params = derive_key_and_params(
            password=password,
            salt=salt,
            argon_params=weak_params
        )

    # Após a correção, a função deve ignorar os parâmetros fracos
    # e retornar os parâmetros de fallback, que são seguros.
    assert returned_params["time_cost"] == FALLBACK_ARGON2_PARAMS["time_cost"]
    assert returned_params["memory_cost"] == FALLBACK_ARGON2_PARAMS["memory_cost"]

    # O paralelismo não é um fator de segurança primário, mas verificamos se foi mantido
    # ou revertido para o fallback. O comportamento esperado é reverter.
    assert returned_params["parallelism"] == FALLBACK_ARGON2_PARAMS["parallelism"]