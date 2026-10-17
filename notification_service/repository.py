"""Database access for the notifications table. Every query is parameterized (?)."""
from shared.db import get_db
from shared.security import crypto, utc_now
from notification_service.models import Notification


class NotificationRepository:
    def create(self, user_id, title, message, notification_type, severity):
        conn = get_db()
        try:
            cur = conn.execute(
                "INSERT INTO notifications (user_id, title, message, notification_type, severity, "
                "status, created_at) VALUES (?, ?, ?, ?, ?, 'Unread', ?)",
                (user_id, title, crypto.encrypt(message), notification_type, severity, utc_now()),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def _query(self, sql, params=()):
        conn = get_db()
        try:
            return [Notification(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    def _scalar(self, sql, params=()):
        conn = get_db()
        try:
            return conn.execute(sql, params).fetchone()[0]
        finally:
            conn.close()

    def get_by_id(self, notification_id):
        rows = self._query("SELECT * FROM notifications WHERE notification_id = ?", (notification_id,))
        return rows[0] if rows else None

    def search(self, filters, limit, offset):
        """filters may contain user_id, notification_type, severity, status (fixed column names)."""
        allowed = ("user_id", "notification_type", "severity", "status")
        where, params = [], []
        for column in allowed:
            if column in filters:
                where.append(f"{column} = ?")
                params.append(filters[column])
        clause = " AND ".join(where) if where else "1=1"
        rows = self._query(f"SELECT * FROM notifications WHERE {clause} "
                           f"ORDER BY notification_id DESC LIMIT ? OFFSET ?", params + [limit, offset])
        total = self._scalar(f"SELECT COUNT(*) FROM notifications WHERE {clause}", params)
        return rows, total

    def unread_count(self, user_id):
        return self._scalar("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND status = 'Unread'",
                            (user_id,))

    def mark_read(self, notification_id):
        conn = get_db()
        try:
            # "AND status = 'Unread'" keeps the first read date if two requests race
            conn.execute("UPDATE notifications SET status = 'Read', read_at = ? "
                         "WHERE notification_id = ? AND status = 'Unread'", (utc_now(), notification_id))
            conn.commit()
        finally:
            conn.close()

    def delete(self, notification_id):
        conn = get_db()
        try:
            cur = conn.execute("DELETE FROM notifications WHERE notification_id = ?", (notification_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()
