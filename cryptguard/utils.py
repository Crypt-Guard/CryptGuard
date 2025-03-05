# utils.py

import os
import datetime
import secrets
import subprocess

def clear_screen():
    subprocess.call('cls' if os.name == 'nt' else 'clear', shell=True)

def generate_ephemeral_token(n_bits=128):
    """
    Retorna um token em hex com n_bits de entropia.
    """
    num = int.from_bytes(secrets.token_bytes((n_bits+7)//8), 'big')
    return hex(num)[2:]

def gerar_numero_aleatorio(n_bits):
    """
    Gera um número pseudoaleatório usando secrets.token_bytes(n_bits).
    """
    random_bytes = secrets.token_bytes((n_bits+7)//8)
    numero = int.from_bytes(random_bytes, 'big')
    excesso = (len(random_bytes)*8 - n_bits)
    if excesso > 0:
        numero >>= excesso
    return numero

def generate_unique_filename(prefix: str, extension: str = ".enc") -> str:
    """
    Gera um nome de arquivo com prefixo, data/hora e componente aleatório.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    random_component = hex(gerar_numero_aleatorio(64))[2:]
    return f"{prefix}_{timestamp}_{random_component}{extension}"
