import sqlite3
import os
from pathlib import Path

def get_db_path():
    """Retorna o caminho do banco de dados"""
    db_dir = Path(os.path.expanduser("~")) / "AppData" / "Local" / "CryptGuard"
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
    try:
        conn = sqlite3.connect(get_db_path()); cur = conn.cursor()
        cur.execute("""
            INSERT INTO tries(file_path, attempts) VALUES(?, 1)
            ON CONFLICT(file_path) DO UPDATE SET attempts = attempts + 1
        """, (file_path,))
        conn.commit()
    finally:
        try: conn.close()
        except: pass

def check_password_attempts(file_path: str, max_attempts: int = 3) -> bool:
    """Verifica se o arquivo ainda pode ser descriptografado"""
    try:
        conn = sqlite3.connect(get_db_path())
        cursor = conn.cursor()
        
        cursor.execute('SELECT attempts FROM tries WHERE file_path = ?', (file_path,))
        result = cursor.fetchone()
        
        conn.close()
        
        if result is None:
            return True
        
        return result[0] < max_attempts
    except Exception:
        return True  # Em caso de erro, permite tentativas