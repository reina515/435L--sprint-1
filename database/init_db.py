"""
Creates the database file and all tables from schema.sql.
    python database/init_db.py
(The services also call init_db() on startup, so this is optional.)
"""
import os
import sqlite3
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.config import DATABASE_PATH   # noqa: E402
from shared.db import init_db             # noqa: E402

if __name__ == "__main__":
    init_db()
    conn = sqlite3.connect(DATABASE_PATH)
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    triggers = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'")]
    conn.close()
    print(f"Database ready: {DATABASE_PATH}")
    print("Tables:  ", ", ".join(tables))
    print("Triggers:", ", ".join(triggers))
