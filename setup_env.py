import os
import secrets
import sys

from cryptography.fernet import Fernet

ROOT = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(ROOT, ".env")

TEMPLATE = """STUDENT_NAME={student}

JWT_SECRET={jwt}
FERNET_KEY={fernet}
HMAC_KEY={hmac}
SERVICE_API_KEY={service}

JWT_EXPIRES_MINUTES=60

DATABASE_PATH=database/security.db

HOST=127.0.0.1
USER_SERVICE_PORT=5001
AUDIT_SERVICE_PORT=5005
NOTIFICATION_SERVICE_PORT=5008
INCIDENT_SERVICE_PORT=5003
THREAT_SERVICE_PORT=5004
PLAYBOOK_SERVICE_PORT=5009

MAX_FAILED_LOGINS=5
FLASK_DEBUG=false
USE_HTTPS=false
"""


# creates the .env file with random secret keys the first time
def main():
    if os.path.exists(ENV_PATH) and "--force" not in sys.argv:
        print(".env already exists, nothing was changed. Use --force to make new keys.")
        return
    student = input("Your full name: ").strip() or "<Your Full Name>"
    content = TEMPLATE.format(
        student=student,
        jwt=secrets.token_urlsafe(48),
        fernet=Fernet.generate_key().decode(),
        hmac=secrets.token_urlsafe(48),
        service=secrets.token_urlsafe(32),
    )
    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.write(content)
    try:
        os.chmod(ENV_PATH, 0o600)
    except OSError:
        pass
    print(f"Created {ENV_PATH}")
    print("Your SERVICE_API_KEY is inside .env if you need it for testing internal calls.")


if __name__ == "__main__":
    main()
