from shared.security import crypto


class User:
    # builds a User from a database row and decrypts the email
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

    # true when the account status is Active
    @property
    def is_active(self):
        return self.account_status == "Active"

    # what i send back in the api, without the password hash
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

    # smaller version of the user that other services get
    def to_public_dict(self):
        return {"user_id": self.user_id, "username": self.username, "full_name": self.full_name,
                "role": self.role, "account_status": self.account_status}
