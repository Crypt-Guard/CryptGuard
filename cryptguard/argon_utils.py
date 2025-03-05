# argon_utils.py

from argon2.low_level import hash_secret_raw, Type
from config import DEFAULT_ARGON_PARAMS, META_ARGON_PARAMS

def generate_key_from_password(password: bytearray, salt: bytes, params: dict):
    """
    Deriva 32 bytes usando Argon2id, retornando-os como bytearray.
    Convertendo 'password' e 'salt' em 'bytes' por compatibilidade com Argon2.
    """
    key_raw = hash_secret_raw(
        secret=bytes(password),
        salt=bytes(salt),
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"],
        hash_len=32,
        type=Type.ID
    )
    return bytearray(key_raw)

def get_argon2_parameters_for_encryption():
    """
    Pergunta ao usuário se deseja customizar Argon2id. Retorna dict.
    """
    default_params = DEFAULT_ARGON_PARAMS
    custom = input("Deseja customizar os parâmetros de Argon2id? (s/n): ").strip().lower()
    if custom != 's':
        return default_params
    while True:
        try:
            time_cost = int(input("Digite time_cost (mínimo 3, padrão 4): "))
            memory_cost = int(input("Digite memory_cost em KiB (mínimo 65536, padrão 102400): "))
            parallelism = int(input("Digite parallelism (mínimo 2, padrão 2): "))

            if time_cost < 3:
                time_cost = 3
            if memory_cost < 65536:
                memory_cost = 102400
            if parallelism < 2:
                parallelism = 2

            return {"time_cost": time_cost, "memory_cost": memory_cost, "parallelism": parallelism}
        except ValueError:
            print("Entrada inválida! Insira apenas números inteiros.")
