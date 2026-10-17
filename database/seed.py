"""
Inserts one sample user per role (the 4 personas) so you can log in and test right away.
    python database/seed.py

The first Security Administrator has to be created this way: through the API,
only an administrator may create privileged accounts. Any additional users
(e.g. new employees) are created through Postman with POST /users/register.

| username | password       | role                   |
|----------|----------------|------------------------|
| admin    | Admin@12345    | Security Administrator |
| analyst  | Analyst@12345  | Security Analyst       |
| employee | Employee@12345 | Regular Employee       |
| auditor  | Auditor@12345  | Auditor                |
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.db import init_db                                  # noqa: E402
from shared.security import PasswordHasher                     # noqa: E402
from user_service.repository import UserRepository             # noqa: E402
from audit_service.repository import AuditLogRepository        # noqa: E402
from notification_service.repository import NotificationRepository  # noqa: E402

SAMPLE_USERS = [
    ("System Administrator", "admin", "admin@security.local", "Admin@12345", "IT Security",
     "Security Administrator", "Active"),
    ("Sara Analyst", "analyst", "analyst@security.local", "Analyst@12345", "SOC",
     "Security Analyst", "Active"),
    ("Omar Employee", "employee", "employee@security.local", "Employee@12345", "Finance",
     "Regular Employee", "Active"),
    ("Adam Auditor", "auditor", "auditor@security.local", "Auditor@12345", "Compliance",
     "Auditor", "Active"),
]


def main():
    init_db()
    users, logs, notes = UserRepository(), AuditLogRepository(), NotificationRepository()
    for full_name, username, email, password, dept, role, status in SAMPLE_USERS:
        if users.get_by_username(username):
            print(f"  - {username:10} already exists, skipped")
            continue
        user_id = users.create(full_name, username, email, PasswordHasher.hash(password), dept, role, status)
        logs.create(user_id, "USER_CREATED", f"Sample user '{username}' created by seed script with role "
                                             f"'{role}'", "Information", "Users")
        notes.create(user_id, "Welcome to the Security Incident Response Platform",
                     f"Hello {full_name}, your account '{username}' is ready.", "System Notification", "Low")
        print(f"  + {username:10} id={user_id:<3} role={role} status={status}")
    print("Seeding finished.")


if __name__ == "__main__":
    main()
