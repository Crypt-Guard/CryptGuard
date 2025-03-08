# config.py

# Parâmetros gerais de chunk
CHUNK_SIZE = 1024 * 1024            # Tamanho padrão de 1 MB
STREAMING_THRESHOLD = 10 * 1024 * 1024  # 10 MB

# Número máximo de tentativas de senha (ex.: em volume oculto)
MAX_ATTEMPTS = 5

# Tamanho do salt usado em metadados
META_SALT_SIZE = 16  # bytes do "meta_salt"

# Parâmetros Argon2id default para arquivos
DEFAULT_ARGON_PARAMS = {
    "time_cost": 4,
    "memory_cost": 102400,
    "parallelism": 2
}

# Parâmetros Argon2id para cifrar metadados (aumentado time_cost para maior segurança)
META_ARGON_PARAMS = {
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 2,
}
