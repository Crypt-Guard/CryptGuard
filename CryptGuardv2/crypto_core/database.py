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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            attempts INTEGER DEFAULT 1
        )
    ''')
    
    conn.commit()
    conn.close()

def record_failed_attempt(file_path: str):
    """Registra uma tentativa falhada de descriptografia"""
    try:
        conn = sqlite3.connect(get_db_path())
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO tries (file_path, attempts)
            VALUES (?, COALESCE((SELECT attempts FROM tries WHERE file_path = ?) + 1, 1))
        ''', (file_path, file_path))
        
        conn.commit()
        conn.close()
    except Exception:
        pass  # Ignora erros de banco de dados

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