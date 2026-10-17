"""Database access for the users table. Every query is parameterized (?)."""
from shared.db import get_db
from shared.security import crypto, utc_now
from user_service.models import User

# Columns a caller is allowed to change through update(); protects against
# building SQL from arbitrary dictionary keys.
UPDATABLE_COLUMNS = {"full_name", "email", "department", "role", "account_status"}


class UserRepository:
    def create(self, full_name, username, email, password_hash, department, role,
               account_status="Active"):
        conn = get_db()
        try:
            cur = conn.execute(
                "INSERT INTO users (full_name, username, email_encrypted, email_hash, password_hash, "
                "department, role, account_status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (full_name, username, crypto.encrypt(email), crypto.blind_index(email), password_hash,
                 department, role, account_status, utc_now()),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def _fetch_one(self, sql, params):
        conn = get_db()
        try:
            row = conn.execute(sql, params).fetchone()
            return User(row) if row else None
        finally:
            conn.close()

    def get_by_id(self, user_id):
        return self._fetch_one("SELECT * FROM users WHERE user_id = ?", (user_id,))

    def get_by_username(self, username):
        # username column is COLLATE NOCASE -> 'Admin' and 'admin' are the same user
        return self._fetch_one("SELECT * FROM users WHERE username = ?", (username,))

    def get_by_email(self, email):
        return self._fetch_one("SELECT * FROM users WHERE email_hash = ?", (crypto.blind_index(email),))

    def email_taken(self, email, exclude_user_id=None):
        user = self.get_by_email(email)
        return user is not None and user.user_id != exclude_user_id

    def list_all(self, limit=100, offset=0, role=None, status=None):
        sql, params = "SELECT * FROM users WHERE 1=1", []
        if role:
            sql += " AND role = ?"
            params.append(role)
        if status:
            sql += " AND account_status = ?"
            params.append(status)
        sql += " ORDER BY user_id LIMIT ? OFFSET ?"
        params += [limit, offset]
        conn = get_db()
        try:
            return [User(r) for r in conn.execute(sql, params).fetchall()]
        finally:
            conn.close()

    def count(self):
        conn = get_db()
        try:
            return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        finally:
            conn.close()

    def update(self, user_id, changes):
        columns, params = [], []
        for column, value in changes.items():
            if column not in UPDATABLE_COLUMNS:
                raise ValueError(f"Column {column} cannot be updated")
            if column == "email":
                columns += ["email_encrypted = ?", "email_hash = ?"]
                params += [crypto.encrypt(value), crypto.blind_index(value)]
            else:
                columns.append(f"{column} = ?")
                params.append(value)
        columns.append("updated_at = ?")
        params += [utc_now(), user_id]
        conn = get_db()
        try:
            conn.execute(f"UPDATE users SET {', '.join(columns)} WHERE user_id = ?", params)
            conn.commit()
        finally:
            conn.close()

    def delete(self, user_id):
        conn = get_db()
        try:
            cur = conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def record_failed_login(self, user_id):
        conn = get_db()
        try:
            conn.execute("UPDATE users SET failed_login_attempts = failed_login_attempts + 1 "
                         "WHERE user_id = ?", (user_id,))
            conn.commit()
            return conn.execute("SELECT failed_login_attempts FROM users WHERE user_id = ?",
                                (user_id,)).fetchone()[0]
        finally:
            conn.close()

    def record_successful_login(self, user_id):
        conn = get_db()
        try:
            conn.execute("UPDATE users SET failed_login_attempts = 0, last_login = ? WHERE user_id = ?",
                         (utc_now(), user_id))
            conn.commit()
        finally:
            conn.close()
