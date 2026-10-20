"""
Database access for the threats table.
Implemented by: Hayam Itani

Rules: parameterised queries only (?); column names in dynamic SQL come from fixed
allow-lists in this file, never from the request.
The table has UNIQUE (threat_type, threat_value), so the database itself also blocks duplicates.
"""
from shared.db import get_db
from shared.security import utc_now
from threat_service.models import Threat


class ThreatRepository:
    """All SQL of the Threat Intelligence Service."""

    UPDATABLE = ("description", "severity", "source")   # brief: possible updates

    def create(self, threat_type, threat_value, description, severity, source):
        """Insert a threat indicator.

        :param threat_type: one of Threat.TYPES
        :type threat_type: str
        :param threat_value: the normalised indicator (IP, domain, hash or text)
        :type threat_value: str
        :param description: what is known about the threat
        :type description: str
        :param severity: Low, Medium, High or Critical
        :type severity: str
        :param source: where the indicator came from
        :type source: str
        :return: the new threat_id
        :rtype: int
        :raises sqlite3.IntegrityError: same type + value already stored (race with another request)
        """
        conn = get_db()
        try:
            cur = conn.execute(
                "INSERT INTO threats (threat_type, threat_value, description, severity, source, date_added) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (threat_type, threat_value, description, severity, source, utc_now()),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


    def get_by_id(self, threat_id):
        """Load one threat indicator.

        :param threat_id: id of the threat
        :type threat_id: int
        :return: the Threat, or None if it does not exist
        :rtype: Threat or None
        """
        conn = get_db()
        try:
            row = conn.execute("SELECT * FROM threats WHERE threat_id = ?", (threat_id,)).fetchone()
        finally:
            conn.close()
        return Threat(row) if row else None


    def find_by_type_and_value(self, threat_type, threat_value):
        """Used before inserting, to return a clean 409 with the existing id.

        :param threat_type: one of Threat.TYPES
        :type threat_type: str
        :param threat_value: the normalised indicator
        :type threat_value: str
        :return: the existing Threat or None
        :rtype: Threat or None
        """
        conn = get_db()
        try:
            row = conn.execute("SELECT * FROM threats WHERE threat_type = ? AND threat_value = ?",
                               (threat_type, threat_value)).fetchone()
        finally:
            conn.close()
        return Threat(row) if row else None


    def search(self, filters, limit, offset):
        """List or search threats, newest first. With no filters it lists everything (GET /threats).

        :param filters: may contain threat_type, severity (exact match),
            threat_value, source (partial match)
        :type filters: dict
        :param limit: page size
        :type limit: int
        :param offset: rows to skip
        :type offset: int
        :return: (threats, total matches)
        :rtype: tuple[list[Threat], int]
        """
        where, params = [], []
        for column in ("threat_type", "severity"):          # exact match
            if column in filters:
                where.append(f"{column} = ?")
                params.append(filters[column])
        for column in ("threat_value", "source"):           # partial match
            if column in filters:
                text = filters[column].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                where.append(f"{column} LIKE ? ESCAPE '\\'")
                params.append(f"%{text}%")
        clause = " AND ".join(where) if where else "1=1"
        conn = get_db()
        try:
            rows = conn.execute(f"SELECT * FROM threats WHERE {clause} "
                                f"ORDER BY threat_id DESC LIMIT ? OFFSET ?",
                                params + [limit, offset]).fetchall()
            total = conn.execute(f"SELECT COUNT(*) FROM threats WHERE {clause}", params).fetchone()[0]
        finally:
            conn.close()
        return [Threat(r) for r in rows], total


    def update(self, threat_id, changes):
        """Update only the columns in UPDATABLE.

        :param threat_id: id of the threat
        :type threat_id: int
        :param changes: {column: new value}, keys already checked against UPDATABLE
        :type changes: dict
        """
        columns = [c for c in self.UPDATABLE if c in changes]
        if not columns:
            return
        assignments = ", ".join(f"{c} = ?" for c in columns)
        conn = get_db()
        try:
            conn.execute(f"UPDATE threats SET {assignments} WHERE threat_id = ?",
                         [changes[c] for c in columns] + [threat_id])
            conn.commit()
        finally:
            conn.close()


    def delete(self, threat_id):
        """Delete one threat indicator.

        :param threat_id: id of the threat
        :type threat_id: int
        :return: True if a row was deleted
        :rtype: bool
        """
        conn = get_db()
        try:
            cur = conn.execute("DELETE FROM threats WHERE threat_id = ?", (threat_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

