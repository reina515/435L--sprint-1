from shared.db import get_db
from shared.security import crypto, utc_now
from audit_service.models import AuditLog


class AuditLogRepository:
    # checks the user id is in the users table
    def user_exists(self, user_id):
        conn = get_db()
        try:
            return conn.execute("SELECT 1 FROM users WHERE user_id = ?", (user_id,)).fetchone() is not None
        finally:
            conn.close()

    # saves a new log with its signature and encrypted description and returns the id
    def create(self, user_id, action, description, severity, related_service):
        conn = get_db()
        try:
            username = None
            if user_id is not None:
                row = conn.execute("SELECT username FROM users WHERE user_id = ?", (user_id,)).fetchone()
                if row is None:
                    fk_user_id = None
                else:
                    fk_user_id, username = user_id, row["username"]
            else:
                fk_user_id = None
            timestamp = utc_now()
            signature = crypto.sign(*AuditLog.signature_parts(
                user_id, username, action, description, timestamp, severity, related_service))
            cur = conn.execute(
                "INSERT INTO logs (user_id, original_user_id, actor_username, action, description, "
                "timestamp, severity, related_service, integrity_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (fk_user_id, user_id, username, action, crypto.encrypt(description), timestamp,
                 severity, related_service, signature),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    # runs a select and gives back AuditLog objects
    def _query(self, sql, params=()):
        conn = get_db()
        try:
            return [AuditLog(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    # runs a query that returns just one number
    def _scalar(self, sql, params=()):
        conn = get_db()
        try:
            return conn.execute(sql, params).fetchone()[0]
        finally:
            conn.close()

    # one log by its id
    def get_by_id(self, log_id):
        rows = self._query("SELECT * FROM logs WHERE log_id = ?", (log_id,))
        return rows[0] if rows else None

    # all logs, newest first, with paging
    def list_all(self, limit, offset):
        return self._query("SELECT * FROM logs ORDER BY log_id DESC LIMIT ? OFFSET ?", (limit, offset))

    # total number of logs
    def count(self):
        return self._scalar("SELECT COUNT(*) FROM logs")

    # logs of one user together with how many there are
    def by_user(self, user_id, limit, offset):
        logs = self._query("SELECT * FROM logs WHERE original_user_id = ? ORDER BY log_id DESC "
                           "LIMIT ? OFFSET ?", (user_id, limit, offset))
        total = self._scalar("SELECT COUNT(*) FROM logs WHERE original_user_id = ?", (user_id,))
        return logs, total

    # builds the search query from the filters using only parameters so no sql injection
    def search(self, filters, limit, offset):
        where, params = [], []
        if "user_id" in filters:
            where.append("original_user_id = ?")
            params.append(filters["user_id"])
        if "username" in filters:
            where.append("actor_username = ? COLLATE NOCASE")
            params.append(filters["username"])
        if "action" in filters:
            where.append("action LIKE ? ESCAPE '\\'")
            escaped = filters["action"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params.append(f"%{escaped}%")
        if "severity" in filters:
            where.append("severity = ?")
            params.append(filters["severity"])
        if "related_service" in filters:
            where.append("related_service = ?")
            params.append(filters["related_service"])
        if "date" in filters:
            where.append("date(timestamp) = ?")
            params.append(filters["date"])
        if "date_from" in filters:
            where.append("date(timestamp) >= ?")
            params.append(filters["date_from"])
        if "date_to" in filters:
            where.append("date(timestamp) <= ?")
            params.append(filters["date_to"])
        clause = " AND ".join(where) if where else "1=1"
        logs = self._query(f"SELECT * FROM logs WHERE {clause} ORDER BY log_id DESC LIMIT ? OFFSET ?",
                           params + [limit, offset])
        total = self._scalar(f"SELECT COUNT(*) FROM logs WHERE {clause}", params)
        return logs, total

    # removes one log and says if it worked
    def delete(self, log_id):
        conn = get_db()
        try:
            cur = conn.execute("DELETE FROM logs WHERE log_id = ?", (log_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()
