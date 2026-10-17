"""
Database access helpers (SQLite).

Security measures from Lab 2 applied here:
  * Parameterized queries only (every repository uses ? placeholders) -> no SQL injection.
  * Foreign keys are switched ON for every connection (SQLite has them OFF by default).
  * The database file gets owner-only permissions (chmod 600).
"""
import os
import sqlite3
import stat

from shared.config import DATABASE_PATH, PROJECT_ROOT

SCHEMA_PATH = os.path.join(PROJECT_ROOT, "database", "schema.sql")


def get_db():
    """Open a new connection. Rows behave like dicts: row["username"]."""
    conn = sqlite3.connect(DATABASE_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def restrict_file_permissions(path):
    """Lab 2 item 4: only the owner may read/write the database file (chmod 600).
    On Windows Python can only toggle the read-only flag, see README for icacls."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def init_db():
    """Create every table/trigger if missing. Safe to run many times."""
    os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        schema = f.read()
    conn = get_db()
    try:
        conn.execute("PRAGMA journal_mode = WAL")  # lets the 3 services read/write concurrently
        conn.executescript(schema)
        conn.commit()
    finally:
        conn.close()
    restrict_file_permissions(DATABASE_PATH)
