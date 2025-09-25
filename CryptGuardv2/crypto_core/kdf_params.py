"""
Calibração e parâmetros padronizados para KDF Argon2id + HKDF

Fornece funções para calibrar Argon2id para ~250-350ms e derivar
sub-chaves nomeadas usando HKDF-SHA256.
"""

import os
import time

from argon2 import low_level
from argon2.low_level import Type as ArgonType

# Parâmetros de fallback (conservadores)
FALLBACK_ARGON2_PARAMS = {
    "time_cost": 3,  # 3 iterações
    "memory_cost": 65536,  # 64 MiB
    "parallelism": 4,  # 4 threads
}

# Limites de segurança
MIN_MEMORY_COST = 8 * 1024  # 8 MiB mínimo
MAX_MEMORY_COST = 1024 * 1024  # 1 GiB máximo
MIN_TIME_COST = 1
MAX_TIME_COST = 10
MIN_PARALLELISM = 1
MAX_PARALLELISM = 8

# Sub-chaves padronizadas
KEY_LABELS = {
    "file_key": b"file-key",  # Para criptografia de arquivos
    "header_key": b"header-key",  # Para autenticação de headers
    "stream_key": b"stream-key",  # Para chaves de streaming
    "vault_key": b"vault-key",  # Para cofres do KeyGuard
}


def calibrate_argon2id(target_ms: float = 250.0, max_mem_mb: int = 256) -> dict[str, int]:
    """
    Calibra parâmetros Argon2id para atingir ~target_ms em tempo de derivação.

    Args:
        target_ms: Tempo alvo em milissegundos (250-350 recomendado)
        max_mem_mb: Memória máxima em MB (limite superior)

    Returns:
        Dict com 'time_cost', 'memory_cost', 'parallelism'

    Raises:
        RuntimeError: Se calibração falhar
    """
    # Começa com parâmetros conservadores
    params = FALLBACK_ARGON2_PARAMS.copy()

    # Limita memória ao máximo especificado
    max_memory_bytes = max_mem_mb * 1024 * 1024
    params["memory_cost"] = min(params["memory_cost"], max_memory_bytes // 1024)

    # Testa parâmetros atuais
    test_password = os.urandom(32)
    test_salt = os.urandom(16)

    try:
        start_time = time.perf_counter()
        low_level.hash_secret_raw(
            secret=test_password,
            salt=test_salt,
            time_cost=params["time_cost"],
            memory_cost=params["memory_cost"],
            parallelism=params["parallelism"],
            hash_len=32,
            type=ArgonType.ID,
        )
        elapsed = (time.perf_counter() - start_time) * 1000  # ms

        # Ajusta se necessário (algoritmo simples: se muito rápido, aumenta; se muito lento, diminui)
        if elapsed < target_ms * 0.8:  # Muito rápido, aumenta custo
            if params["time_cost"] < MAX_TIME_COST:
                params["time_cost"] += 1
            elif params["memory_cost"] * 1024 < max_memory_bytes:
                params["memory_cost"] = min(params["memory_cost"] * 2, max_memory_bytes // 1024)

        elif elapsed > target_ms * 1.2:  # Muito lento, diminui custo
            if params["time_cost"] > MIN_TIME_COST:
                params["time_cost"] = max(1, params["time_cost"] - 1)
            elif params["memory_cost"] > MIN_MEMORY_COST:
                params["memory_cost"] = max(MIN_MEMORY_COST, params["memory_cost"] // 2)

    except Exception:
        # Se calibração falha, usa fallback
        pass

    # Valida limites
    params["memory_cost"] = max(MIN_MEMORY_COST, min(MAX_MEMORY_COST, params["memory_cost"]))
    params["time_cost"] = max(MIN_TIME_COST, min(MAX_TIME_COST, params["time_cost"]))
    params["parallelism"] = max(MIN_PARALLELISM, min(MAX_PARALLELISM, params["parallelism"]))

    return params


def derive_key_and_params(
    password: bytes,
    salt: bytes,
    key_label: str = "file_key",
    argon_params: dict[str, int] | None = None,
    hkdf_salt: bytes | None = None,
) -> tuple[bytes, dict[str, int]]:
    """
    Deriva chave usando Argon2id + HKDF com parâmetros calibrados.

    Args:
        password: Senha mestre
        salt: Salt para Argon2id (16 bytes recomendado)
        key_label: Rótulo da sub-chave (ver KEY_LABELS)
        argon_params: Parâmetros Argon2id (usa calibração se None)
        hkdf_salt: Salt para HKDF (16 bytes recomendado, aleatório se None)

    Returns:
        Tuple[chave_derivada, parâmetros_usados]

    Raises:
        ValueError: Se parâmetros inválidos
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if len(salt) < 8:
        raise ValueError("Salt deve ter pelo menos 8 bytes")

    if key_label not in KEY_LABELS:
        raise ValueError(f"Key label desconhecido: {key_label}")

    # Usa parâmetros calibrados se não fornecidos
    if argon_params is None:
        argon_params = get_cached_params()

    # Deriva chave mestre com Argon2id
    master_key = low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=argon_params["time_cost"],
        memory_cost=argon_params["memory_cost"],
        parallelism=argon_params["parallelism"],
        hash_len=32,
        type=ArgonType.ID,
    )

    # Para compatibilidade com CG2, vaults usam a master_key diretamente sem HKDF
    if key_label == "vault_key":
        return master_key, argon_params

    # Deriva sub-chave específica com HKDF para outros usos
    hkdf_salt = hkdf_salt or os.urandom(16)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=KEY_LABELS[key_label],
    )

    derived_key = hkdf.derive(master_key)

    return derived_key, argon_params


def generate_salt() -> bytes:
    """Gera salt aleatório de 16 bytes para uso geral."""
    return os.urandom(16)


def get_default_params() -> dict[str, int]:
    """Retorna parâmetros padrão calibrados para uso geral."""
    return calibrate_argon2id()


# Cache de parâmetros (evita recalibração excessiva)
_cached_params: dict[str, int] | None = None


def get_cached_params() -> dict[str, int]:
    """Retorna parâmetros calibrados em cache ou carrega do arquivo se necessário."""
    global _cached_params
    if _cached_params is None:
        # Tenta carregar parâmetros salvos primeiro
        try:
            import json

            from crypto_core.paths import BASE_DIR

            calib_path = BASE_DIR / "argon_calib.json"
            if calib_path.exists():
                with open(calib_path) as f:
                    data = json.load(f)
                    # Usa parâmetros BALANCED se disponíveis, senão FAST
                    if "BALANCED" in data:
                        _cached_params = {
                            "time_cost": data["BALANCED"]["time"],
                            "memory_cost": data["BALANCED"]["mem"],
                            "parallelism": data["BALANCED"]["par"],
                        }
                    elif "FAST" in data:
                        _cached_params = {
                            "time_cost": data["FAST"]["time"],
                            "memory_cost": data["FAST"]["mem"],
                            "parallelism": data["FAST"]["par"],
                        }
                    else:
                        # Fallback para calibração se arquivo não tem estrutura esperada
                        _cached_params = calibrate_argon2id()
            else:
                _cached_params = calibrate_argon2id()
        except Exception:
            # Fallback para calibração se houver erro ao carregar
            _cached_params = calibrate_argon2id()
    return _cached_params
