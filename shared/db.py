import os
import sqlite3
import stat

from shared.config import DATABASE_PATH, PROJECT_ROOT

SCHEMA_PATH = os.path.join(PROJECT_ROOT, "database", "schema.sql")


# opens a connection to the database with foreign keys turned on
def get_db():
    conn = sqlite3.connect(DATABASE_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


# only the owner can read and write this file
def restrict_file_permissions(path):
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


# creates the tables from schema.sql, it is safe to call it many times
def init_db():
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = f.read()
    conn = get_db()
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(schema)
        conn.commit()
    finally:
        conn.close()
    restrict_file_permissions(DATABASE_PATH)
