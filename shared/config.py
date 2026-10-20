import os
from dotenv import load_dotenv

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))


# reads a setting from .env and stops the program if it is missing
def _required(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"Missing setting '{name}'. Run `python setup_env.py` in the project root "
            f"to create the .env file."
        )
    return value


# reads a true or false setting from .env
def _bool(name, default="false"):
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


STUDENT_NAME = os.getenv("STUDENT_NAME", "<Your Full Name>")

ROUTE_PREFIX = "/Reina_Hani"

JWT_SECRET = _required("JWT_SECRET")
FERNET_KEY = _required("FERNET_KEY")
HMAC_KEY = _required("HMAC_KEY")
SERVICE_API_KEY = _required("SERVICE_API_KEY")

JWT_ALGORITHM = "HS256"
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "60"))

DATABASE_PATH = os.getenv("DATABASE_PATH") or os.path.join(PROJECT_ROOT, "database", "security.db")
if not os.path.isabs(DATABASE_PATH):
    DATABASE_PATH = os.path.join(PROJECT_ROOT, DATABASE_PATH)
BACKUP_DIR = os.path.join(PROJECT_ROOT, "backups")
LOG_DIR = os.path.join(PROJECT_ROOT, "logs")

USE_HTTPS = _bool("USE_HTTPS")
SSL_CERT_FILE = os.path.join(PROJECT_ROOT, "certs", "cert.pem")
SSL_KEY_FILE = os.path.join(PROJECT_ROOT, "certs", "key.pem")
_SCHEME = "https" if USE_HTTPS else "http"

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

FLASK_DEBUG = _bool("FLASK_DEBUG")

MAX_FAILED_LOGINS = int(os.getenv("MAX_FAILED_LOGINS", "5"))
