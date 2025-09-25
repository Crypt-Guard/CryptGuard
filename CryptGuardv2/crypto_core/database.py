import os
import sqlite3
import threading
from functools import wraps

from .log_utils import log_best_effort
from .paths import BASE_DIR

_DB_LOCK = threading.RLock()


def get_db_path():
    """Return database path under BASE_DIR."""
    db_dir = BASE_DIR
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "crypto.db"


def _connect():
    return sqlite3.connect(get_db_path(), timeout=5, isolation_level=None)


def _configure_connection(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=FULL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA temp_store=MEMORY;")
    except Exception as exc:
        log_best_effort(__name__, exc)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tries (
            file_path TEXT PRIMARY KEY,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            attempts  INTEGER NOT NULL DEFAULT 0
        )
        """
    )


def _with_conn(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        with _DB_LOCK, _connect() as conn:
            _configure_connection(conn)
            return fn(conn, *args, **kwargs)

    return wrapper


def init_db():
    """Ensure database schema exists and fsync the parent directory."""
    db_path = get_db_path()
    with _DB_LOCK:
        with _connect() as conn:
            _configure_connection(conn)
        try:
            if os.name != "nt":
                flags = getattr(os, "O_RDONLY", 0)
                if hasattr(os, "O_DIRECTORY"):
                    flags |= os.O_DIRECTORY
                dir_fd = os.open(str(db_path.parent), flags)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        except Exception as exc:
            log_best_effort(__name__, exc)


@_with_conn
def record_failed_attempt(conn: sqlite3.Connection, file_path: str):
    """Increment failure counter for file_path."""
    conn.execute(
        """
        INSERT INTO tries(file_path, attempts) VALUES(?, 1)
        ON CONFLICT(file_path) DO UPDATE SET
            attempts = attempts + 1,
            timestamp = CURRENT_TIMESTAMP
        """,
        (file_path,),
    )


@_with_conn
def check_password_attempts(
    conn: sqlite3.Connection, file_path: str, max_attempts: int = 3
) -> bool:
    """Return True when decrypt attempts remain for the given file."""
    try:
        row = conn.execute(
            "SELECT attempts FROM tries WHERE file_path = ?", (file_path,)
        ).fetchone()
        if row is None:
            return True
        return int(row[0]) < max_attempts
    except Exception:
        return True


@_with_conn
def reset_failed_attempts(conn: sqlite3.Connection, file_path: str) -> None:
    """Clear tracked attempts for file_path."""
    conn.execute("DELETE FROM tries WHERE file_path = ?", (file_path,))
