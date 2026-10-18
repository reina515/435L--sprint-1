"""
Database access for the incidents and investigation_notes tables.
Implemented by: Hayam Itani

Rules (same as Reina's repositories):
  * Parameterised queries only (?). Never put request values into SQL with f-strings -> no SQL injection.
  * conn = get_db(); try: ... finally: conn.close()
  * When a WHERE clause is built from filters, the COLUMN NAMES come from a fixed allow-list in this
    file, never from the request. See NotificationRepository.search() for the pattern.
"""
from shared.db import get_db
from shared.security import utc_now
from incident_service.models import Incident, InvestigationNote


class IncidentRepository:
    """All SQL of the Incident Management Service."""

    def create(self, title, description, category, severity, reporter_id, asset_id):
        """Insert a new incident with status 'Open'.

        :return: the new incident_id (cursor.lastrowid)
        :rtype: int
        """
        conn = get_db()
        try:
            cur = conn.execute(
                "INSERT INTO incidents (title, description, category, severity, reporter_id, asset_id, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'Open', ?)",
                (title, description, category, severity, reporter_id, asset_id, utc_now()),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def get_by_id(self, incident_id):
        """Load one incident with its notes.

        :param incident_id: incident id
        :type incident_id: int
        :return: Incident (notes oldest first) or None if it does not exist
        :rtype: Incident or None
        """
        conn = get_db()
        try:
            row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return Incident(row, notes=self.get_notes(incident_id))

    def list(self, filters, limit, offset):
        """List incidents, newest first.

        :param filters: may contain reporter_id, assigned_analyst_id, status, severity
        :type filters: dict
        :param limit: page size
        :param offset: rows to skip
        :return: (incidents, total number of matches before limit/offset)
        :rtype: tuple[list[Incident], int]
        """
        allowed = ("reporter_id", "assigned_analyst_id", "status", "severity")
        where, params = [], []
        for column in allowed:
            if column in filters:
                where.append(f"{column} = ?")
                params.append(filters[column])
        clause = " AND ".join(where) if where else "1=1" # always true
        conn = get_db()
        try:
            rows = conn.execute(f"SELECT * FROM incidents WHERE {clause} ORDER BY incident_id DESC LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
            total = conn.execute(f"SELECT COUNT(*) FROM incidents WHERE {clause}", params).fetchone()[0]
        finally:
            conn.close()
        incidents = [Incident(row, notes=self.get_notes(row["incident_id"])) for row in rows]
        return incidents, total
        

    def asset_exists(self, asset_id):
        """TEMPORARY check until Member B exposes GET /internal/assets/{id}.

        :rtype: bool
        """
        conn = get_db()
        try:
            row = conn.execute("SELECT 1 FROM assets WHERE asset_id = ?", (asset_id,)).fetchone() is not None
        finally:
            conn.close()
        return row

    def assign(self, incident_id, analyst_id):
        """Set assigned_analyst_id on one incident."""
        conn = get_db()
        try:
            conn.execute("UPDATE incidents SET assigned_analyst_id = ? WHERE incident_id = ?", (analyst_id, incident_id))
            conn.commit()
        finally:
            conn.close()

    def update_status(self, incident_id, old_status, new_status):
        """Move an incident one lifecycle step; set resolved_at when new_status is 'Resolved'.

        Put ``AND status = ?`` (old_status) in the WHERE: if two requests arrive together,
        only the first one changes the row.

        :return: True if the row changed, False if someone changed it first
        :rtype: bool
        """
        resolved_at = utc_now() if new_status == "Resolved" else None
        conn = get_db()
        try:
            cur = conn.execute(
                "UPDATE incidents SET status = ?, resolved_at = COALESCE(resolved_at, ?) WHERE incident_id = ? AND status = ?",
                (new_status, resolved_at, incident_id, old_status),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def add_note(self, incident_id, analyst_id, content):
        """Insert an investigation note linked to one incident (FK incident_id).

        :return: the new note_id
        :rtype: int
        """
        conn = get_db()
        try:
            cur = conn.execute(
                "INSERT INTO investigation_notes (incident_id, analyst_id, content, created_at) "
                "VALUES (?, ?, ?, ?)",
                (incident_id, analyst_id, content, utc_now()),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def get_notes(self, incident_id):
        """All notes of one incident, oldest first.

        :rtype: list[InvestigationNote]
        """
        conn = get_db()
        try:
            rows = conn.execute("SELECT * FROM investigation_notes WHERE incident_id = ? ORDER BY note_id", (incident_id,)).fetchall()
            return [InvestigationNote(row) for row in rows]
        finally:
            conn.close()
