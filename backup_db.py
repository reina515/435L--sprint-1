import glob
import os
import sqlite3
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.config import BACKUP_DIR, DATABASE_PATH
from shared.db import restrict_file_permissions

KEEP_LAST = 10


# copies the database into the backups folder and keeps only the last 10 copies
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
