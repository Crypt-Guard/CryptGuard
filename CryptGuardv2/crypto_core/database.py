import sqlite3
import os
from pathlib import Path
from .paths import BASE_DIR

def get_db_path():
    """Retorna o caminho do banco de dados"""
    db_dir = BASE_DIR
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "crypto.db"

def init_db():
    """Inicializa o banco de dados com as tabelas necessárias"""
    db_path = get_db_path()
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Cria a tabela tries se não existir
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tries (
            file_path TEXT PRIMARY KEY,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            attempts  INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()

def record_failed_attempt(file_path: str):
    """Registra uma tentativa falha e atualiza o timestamp."""
    init_db()
    with sqlite3.connect(get_db_path(), timeout=5) as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO tries(file_path, attempts) VALUES(?, 1)
            ON CONFLICT(file_path) DO UPDATE SET
                attempts = attempts + 1,
                timestamp = CURRENT_TIMESTAMP
        """, (file_path,))
        # with-context commits automatically on success

def check_password_attempts(file_path: str, max_attempts: int = 3) -> bool:
    """Verifica se o arquivo ainda pode ser descriptografado"""
    try:
        init_db()
        with sqlite3.connect(get_db_path(), timeout=5) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT attempts FROM tries WHERE file_path = ?', (file_path,))
            result = cursor.fetchone()
        if result is None:
            return True
        return result[0] < max_attempts
    except Exception:
        return True  # Em caso de erro, permite tentativas

def reset_failed_attempts(file_path: str) -> None:
    """Reseta/limpa as tentativas registradas para um arquivo."""
    init_db()
    with sqlite3.connect(get_db_path(), timeout=5) as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM tries WHERE file_path = ?', (file_path,))
        # ...no explicit commit needed due to context manager...