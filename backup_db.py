"""
Database backup (Lab 2 item 8: "Backup Database Regularly").

    python backup_db.py            # creates backups/security_YYYYMMDD_HHMMSS.db, keeps the last 10

Uses SQLite's online backup API, so it is safe while the services are running.
To automate it on Windows, create a Task Scheduler task that runs:
    python "C:\\...\\sprint1\\backup_db.py"
(on Linux/macOS: a cron job, e.g.  0 2 * * * python3 /path/sprint1/backup_db.py)
"""
import glob
import os
import sqlite3
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.config import BACKUP_DIR, DATABASE_PATH       # noqa: E402
from shared.db import restrict_file_permissions           # noqa: E402

KEEP_LAST = 10


def backup():
    if not os.path.exists(DATABASE_PATH):
        print(f"No database found at {DATABASE_PATH}")
        return None
    os.makedirs(BACKUP_DIR, exist_ok=True)
    target = os.path.join(BACKUP_DIR, f"security_{datetime.now():%Y%m%d_%H%M%S}.db")
    source = sqlite3.connect(DATABASE_PATH)
    dest = sqlite3.connect(target)
    try:
        with dest:
            source.backup(dest)
    finally:
        dest.close()
        source.close()
    restrict_file_permissions(target)

    old = sorted(glob.glob(os.path.join(BACKUP_DIR, "security_*.db")))[:-KEEP_LAST]
    for path in old:
        os.remove(path)
    print(f"Backup written to {target}")
    return target


if __name__ == "__main__":
    backup()
