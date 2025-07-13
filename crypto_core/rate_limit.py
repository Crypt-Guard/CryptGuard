"""
rate_limit.py – atraso exponencial local.

Banco: %USERPROFILE%\\.cryptguard\\attempts.db
Tabela: tries(id TEXT PK, count INT, next REAL)
"""
import sqlite3, hashlib, os, time
from pathlib import Path

_DB = Path.home() / ".cryptguard" / "attempts.db"
_DB.parent.mkdir(parents=True, exist_ok=True)

# ── setup único (cria tabela se não existir) ───────────────────────────
with sqlite3.connect(_DB) as _c:
    _c.execute("CREATE TABLE IF NOT EXISTS tries "
               "(id TEXT PRIMARY KEY, count INT, next REAL)")

def _conn():               # conexão helper
    return sqlite3.connect(_DB, detect_types=sqlite3.PARSE_DECLTYPES)

def _hash_header(path: str | os.PathLike, nbytes: int = 512) -> str:
    with open(path, "rb") as f:
        head = f.read(nbytes)
    return hashlib.sha256(head).hexdigest()

# ── API ────────────────────────────────────────────────────────────────
def check_allowed(path) -> bool:
    h = _hash_header(path)
    with _conn() as c:
        row = c.execute("SELECT next FROM tries WHERE id=?", (h,)).fetchone()
        return row is None or row[0] <= time.time()

def register_failure(path) -> int:
    h = _hash_header(path)
    with _conn() as c:
        row = c.execute("SELECT count FROM tries WHERE id=?", (h,)).fetchone()
        new_cnt = (row[0] + 1) if row else 1
        wait    = 2 ** (new_cnt - 1)
        c.execute("REPLACE INTO tries VALUES (?,?,?)",
                  (h, new_cnt, time.time() + wait))
    return wait

def reset(path) -> None:
    h = _hash_header(path)
    with _conn() as c:
        c.execute("DELETE FROM tries WHERE id=?", (h,))
