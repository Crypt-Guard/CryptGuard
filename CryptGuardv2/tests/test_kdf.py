import sys
import os
import pytest

# Adiciona o diretório raiz do projeto ao sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from crypto_core.kdf import derive_key_sb, _validate_argon2id_rfc9106

def test_derive_key_sb_rejects_insecure_params():
    """
    Verifica que a função de compatibilidade derive_key_sb rejeita
    parâmetros Argon2id que violam as regras de segurança.
    """
    password = b"mysecretpassword"

    # Caso 1: Salt muito curto
    insecure_params_short_salt = {
        "salt": "deadbeef", # 4 bytes
        "time_cost": 1,
        "memory_cost": 65536,
        "parallelism": 1,
    }
    with pytest.raises(ValueError, match="Salt .* deve ter no mínimo 16 bytes"):
        derive_key_sb(password, insecure_params_short_salt)

    # Caso 2: memory_cost muito baixo
    insecure_params_mem_cost = {
        "salt": "deadbeefdeadbeefdeadbeefdeadbeef",
        "time_cost": 1,
        "memory_cost": 1024, # 1 MiB, abaixo do mínimo de 16 MiB
        "parallelism": 1,
    }
    with pytest.raises(ValueError, match="memory_cost .* fora da faixa segura"):
        derive_key_sb(password, insecure_params_mem_cost)

    # Caso 3: Parâmetros válidos devem passar
    secure_params = {
        "salt": "deadbeefdeadbeefdeadbeefdeadbeef",
        "time_cost": 1,
        "memory_cost": 65536,
        "parallelism": 4,
    }
    key = derive_key_sb(password, secure_params)
    assert key is not None
    key.clear()

def test_validate_argon2_params_rfc9106_coverage():
    """Testa casos de falha adicionais para a função de validação centralizada."""
    # time_cost muito baixo
    with pytest.raises(ValueError, match="time_cost .* fora da faixa"):
        _validate_argon2id_rfc9106(t=0, m_kib=65536, p=1, salt_len=16)

    # parallelism muito alto
    with pytest.raises(ValueError, match="parallelism .* fora da faixa"):
        _validate_argon2id_rfc9106(t=1, m_kib=65536, p=10, salt_len=16)

    # A regra m_kib >= 8 * p é implicitamente coberta por MIN_M_KIB,
    # uma vez que MIN_M_KIB (16384) > 8 * MAX_P (32).
    # Portanto, um teste específico para essa regra não é necessário
    # com as constantes atuais.

    # Teste de versão da lib
    try:
        _validate_argon2id_rfc9106(t=1, m_kib=65536, p=1, salt_len=16)
    except UserWarning as w:
        assert "Versão da biblioteca Argon2" in str(w)
    except RuntimeError as e:
        assert "Versão da biblioteca Argon2" in str(e)