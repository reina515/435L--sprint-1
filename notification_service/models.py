"""Notification domain model (Notification and Alert Management Service)."""
from shared.security import crypto


class Notification:
    """One row of the `notifications` table. The message is stored encrypted."""

    def __init__(self, row):
        self.notification_id = row["notification_id"]
        self.user_id = row["user_id"]
        self.title = row["title"]
        self.message = crypto.decrypt(row["message"])
        self.notification_type = row["notification_type"]
        self.severity = row["severity"]
        self.status = row["status"]
        self.created_at = row["created_at"]
        self.read_at = row["read_at"]

    @property
    def is_read(self):
        return self.status == "Read"

    def to_dict(self):
        return {
            "notification_id": self.notification_id,
            "user_id": self.user_id,
            "title": self.title,
            "message": self.message,
            "notification_type": self.notification_type,
            "severity": self.severity,
            "status": self.status,
            "created_at": self.created_at,
            "read_at": self.read_at,
        }
