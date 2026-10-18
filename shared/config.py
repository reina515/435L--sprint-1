"""
Central configuration for every service.

All secrets (JWT secret, encryption key, service key...) are read from the
.env file in the project root, never hard-coded in the source code
(Lab 2 recommendation: "store the key safely, outside the codebase").
Run `python setup_env.py` once to generate a .env file with random keys.
"""
import os
from dotenv import load_dotenv

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))


def _required(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"Missing setting '{name}'. Run `python setup_env.py` in the project root "
            f"to create the .env file."
        )
    return value


def _bool(name, default="false"):
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


# Name shown on every route (project rule: each API route must state the student's full name)
STUDENT_NAME = os.getenv("STUDENT_NAME", "<Your Full Name>")

# ---------- Secrets ----------
JWT_SECRET = _required("JWT_SECRET")              # signs login tokens
FERNET_KEY = _required("FERNET_KEY")              # encrypts sensitive DB columns
HMAC_KEY = _required("HMAC_KEY")                  # email lookup index + audit-log integrity
SERVICE_API_KEY = _required("SERVICE_API_KEY")    # service-to-service calls

JWT_ALGORITHM = "HS256"
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "60"))

# ---------- Database ----------
DATABASE_PATH = os.getenv("DATABASE_PATH") or os.path.join(PROJECT_ROOT, "database", "security.db")
if not os.path.isabs(DATABASE_PATH):
    DATABASE_PATH = os.path.join(PROJECT_ROOT, DATABASE_PATH)
BACKUP_DIR = os.path.join(PROJECT_ROOT, "backups")
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")

# ---------- HTTPS (optional, Lab 2 item 11) ----------
USE_HTTPS = _bool("USE_HTTPS")
SSL_CERT_FILE = os.path.join(PROJECT_ROOT, "certs", "cert.pem")
SSL_KEY_FILE = os.path.join(PROJECT_ROOT, "certs", "key.pem")
_SCHEME = "https" if USE_HTTPS else "http"

# ---------- Service locations ----------
HOST = os.getenv("HOST", "127.0.0.1")
USER_SERVICE_PORT = int(os.getenv("USER_SERVICE_PORT", "5001"))
INCIDENT_SERVICE_PORT = int(os.getenv("INCIDENT_SERVICE_PORT", "5003"))
THREAT_SERVICE_PORT = int(os.getenv("THREAT_SERVICE_PORT", "5004"))
PLAYBOOK_SERVICE_PORT = int(os.getenv("PLAYBOOK_SERVICE_PORT", "5009"))
AUDIT_SERVICE_PORT = int(os.getenv("AUDIT_SERVICE_PORT", "5005"))
NOTIFICATION_SERVICE_PORT = int(os.getenv("NOTIFICATION_SERVICE_PORT", "5008"))

USER_SERVICE_URL = os.getenv("USER_SERVICE_URL", f"{_SCHEME}://{HOST}:{USER_SERVICE_PORT}")
AUDIT_SERVICE_URL = os.getenv("AUDIT_SERVICE_URL", f"{_SCHEME}://{HOST}:{AUDIT_SERVICE_PORT}")
NOTIFICATION_SERVICE_URL = os.getenv("NOTIFICATION_SERVICE_URL",
                                     f"{_SCHEME}://{HOST}:{NOTIFICATION_SERVICE_PORT}")
INCIDENT_SERVICE_URL = os.getenv("INCIDENT_SERVICE_URL", f"{_SCHEME}://{HOST}:{INCIDENT_SERVICE_PORT}")
THREAT_SERVICE_URL = os.getenv("THREAT_SERVICE_URL", f"{_SCHEME}://{HOST}:{THREAT_SERVICE_PORT}")
PLAYBOOK_SERVICE_URL = os.getenv("PLAYBOOK_SERVICE_URL", f"{_SCHEME}://{HOST}:{PLAYBOOK_SERVICE_PORT}")

SERVICE_TIMEOUT_SECONDS = float(os.getenv("SERVICE_TIMEOUT_SECONDS", "3"))

# Debug mode exposes the Werkzeug debugger, so it is OFF unless explicitly enabled
FLASK_DEBUG = _bool("FLASK_DEBUG")

# Brute-force detection: this many consecutive failed logins raises a Critical alert
MAX_FAILED_LOGINS = int(os.getenv("MAX_FAILED_LOGINS", "5"))
