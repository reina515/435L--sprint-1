from shared.db import get_db
from shared.security import crypto, utc_now
from notification_service.models import Notification


class NotificationRepository:
    # inserts a new unread notification with the message encrypted
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

    # runs a select and returns Notification objects
    def _query(self, sql, params=()):
        conn = get_db()
        try:
            return [Notification(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    # returns a single value like a count
    def _scalar(self, sql, params=()):
        conn = get_db()
        try:
            return conn.execute(sql, params).fetchone()[0]
        finally:
            conn.close()

    # one notification by id, or None
    def get_by_id(self, notification_id):
        rows = self._query("SELECT * FROM notifications WHERE notification_id = ?", (notification_id,))
        return rows[0] if rows else None

    # searches by user, type, severity and status and also returns the total
    def search(self, filters, limit, offset):
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

    # how many unread notifications a user has
    def unread_count(self, user_id):
        return self._scalar("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND status = 'Unread'",
                            (user_id,))

    # marks it as Read and saves the read date only the first time
    def mark_read(self, notification_id):
        conn = get_db()
        try:
            conn.execute("UPDATE notifications SET status = 'Read', read_at = ? "
                         "WHERE notification_id = ? AND status = 'Unread'", (utc_now(), notification_id))
            conn.commit()
        finally:
            conn.close()

    # deletes a notification and says if it existed
    def delete(self, notification_id):
        conn = get_db()
        try:
            cur = conn.execute("DELETE FROM notifications WHERE notification_id = ?", (notification_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()
