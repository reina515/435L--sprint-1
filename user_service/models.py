"""User domain model (Users and Identity Management Service)."""
from shared.security import crypto


class User:
    """One row of the `users` table.

    The email is stored encrypted, so it is decrypted here when the object is built.
    password_hash and email_hash are kept on the object for internal use but are
    NEVER included in API responses (see to_dict).
    """

    def __init__(self, row):
        self.user_id = row["user_id"]
        self.full_name = row["full_name"]
        self.username = row["username"]
        self.email = crypto.decrypt(row["email_encrypted"])
        self.password_hash = row["password_hash"]
        self.department = row["department"]
        self.role = row["role"]
        self.account_status = row["account_status"]
        self.failed_login_attempts = row["failed_login_attempts"]
        self.created_at = row["created_at"]
        self.updated_at = row["updated_at"]
        self.last_login = row["last_login"]

    @property
    def is_active(self):
        return self.account_status == "Active"

    def to_dict(self):
        return {
            "user_id": self.user_id,
            "full_name": self.full_name,
            "username": self.username,
            "email": self.email,
            "department": self.department,
            "role": self.role,
            "account_status": self.account_status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_login": self.last_login,
            "failed_login_attempts": self.failed_login_attempts,
        }

    def to_public_dict(self):
        """Minimal view returned to other services through /internal endpoints."""
        return {"user_id": self.user_id, "username": self.username, "full_name": self.full_name,
                "role": self.role, "account_status": self.account_status}
