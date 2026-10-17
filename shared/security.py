"""
Security toolbox shared by every service (Lab 2 "cybersecurity defenses"):

  1. Password hashing          -> bcrypt (salted, slow hash; plain passwords never stored)
  2. Encryption of sensitive data -> Fernet from the `cryptography` library
  3. Blind index               -> HMAC-SHA256 so encrypted emails can still be searched
  4. Integrity signatures      -> HMAC-SHA256 to detect tampering with audit logs
  5. Input sanitization / validation (type checks, length limits, allowed values,
     rejection of control characters and HTML/script markup)
"""
import hashlib
import hmac
import re
from datetime import datetime, timezone

import bcrypt
from cryptography.fernet import Fernet, InvalidToken

from shared.config import FERNET_KEY, HMAC_KEY
from shared.errors import ValidationError


# =====================================================================
# 1. Password hashing
# =====================================================================
class PasswordHasher:
    ROUNDS = 12  # work factor: 2^12 iterations, makes brute force slow

    @staticmethod
    def hash(plain_password):
        return bcrypt.hashpw(plain_password.encode("utf-8"),
                             bcrypt.gensalt(rounds=PasswordHasher.ROUNDS)).decode("utf-8")

    @staticmethod
    def verify(plain_password, password_hash):
        try:
            return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
        except (ValueError, TypeError):
            return False


# A valid hash of a random value, used so a login for an unknown username takes
# the same time as a wrong password (prevents discovering usernames by timing).
DUMMY_PASSWORD_HASH = PasswordHasher.hash("timing-attack-protection-dummy")


# =====================================================================
# 2-4. Encryption, blind index, integrity signature
# =====================================================================
class CryptoManager:
    def __init__(self, fernet_key, hmac_key):
        self._cipher = Fernet(fernet_key.encode() if isinstance(fernet_key, str) else fernet_key)
        self._hmac_key = hmac_key.encode()

    def encrypt(self, plain_text):
        """Fernet = AES-128-CBC + HMAC-SHA256. Output is a URL-safe text token."""
        if plain_text is None:
            return None
        return self._cipher.encrypt(plain_text.encode("utf-8")).decode("utf-8")

    def decrypt(self, token):
        if token is None:
            return None
        try:
            return self._cipher.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            # Wrong key or corrupted value: never crash, never leak the ciphertext
            return "[unable to decrypt]"

    def blind_index(self, value):
        """Deterministic keyed hash, used to look up an encrypted value (e.g. email)."""
        return hmac.new(self._hmac_key, value.strip().lower().encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def sign(self, *parts):
        """HMAC signature over several values (used for audit-log integrity)."""
        message = "\x1f".join("" if p is None else str(p) for p in parts)
        return hmac.new(self._hmac_key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_signature(self, signature, *parts):
        return hmac.compare_digest(signature or "", self.sign(*parts))


crypto = CryptoManager(FERNET_KEY, HMAC_KEY)


# =====================================================================
# 5. Validation and sanitization
# =====================================================================
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,30}$")
NAME_RE = re.compile(r"^[A-Za-zÀ-ɏ؀-ۿ' .\-]{2,100}$")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MARKUP_RE = re.compile(r"[<>]")
DATE_FMT = "%Y-%m-%d"

ROLES = ("Security Administrator", "Security Analyst", "Regular Employee", "Auditor")
ACCOUNT_STATUSES = ("Active", "Inactive", "Suspended")
LOG_SEVERITIES = ("Information", "Warning", "Error", "Critical")
NOTIFICATION_TYPES = ("Incident Assignment", "Security Alert", "System Notification",
                      "Threat Alert", "Vulnerability Alert")
NOTIFICATION_SEVERITIES = ("Low", "Medium", "High", "Critical")
NOTIFICATION_STATUSES = ("Unread", "Read")
SERVICES = ("Users", "Assets", "Incidents", "Threat Intelligence", "Audit Logging",
            "Reports", "Vulnerabilities", "Notifications", "Playbooks")


def require_json_object(data):
    """Reject empty bodies, non-JSON bodies and JSON that is not an object."""
    if data is None:
        raise ValidationError("Request body must be valid JSON (Content-Type: application/json)")
    if not isinstance(data, dict):
        raise ValidationError("Request body must be a JSON object")
    if not data:
        raise ValidationError("Request body cannot be empty")
    return data


def reject_unknown_fields(data, allowed):
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        raise ValidationError(f"Unexpected field(s): {', '.join(unknown)}",
                              {"allowed_fields": sorted(allowed)})


def require_fields(data, fields):
    missing = [f for f in fields
               if data.get(f) is None or (isinstance(data.get(f), str) and not data[f].strip())]
    if missing:
        raise ValidationError(f"Missing required field(s): {', '.join(missing)}")


def clean_text(value, field, min_len=1, max_len=255, multiline=False):
    """Sanitize free text: type check, strip, length limits, no control chars, no markup."""
    if not isinstance(value, str):
        raise ValidationError(f"'{field}' must be a string")
    value = value.strip()
    if not multiline:
        value = re.sub(r"\s+", " ", value)
    if len(value) < min_len:
        raise ValidationError(f"'{field}' must be at least {min_len} character(s)")
    if len(value) > max_len:
        raise ValidationError(f"'{field}' must be at most {max_len} characters")
    if CONTROL_CHARS_RE.search(value):
        raise ValidationError(f"'{field}' contains invalid control characters")
    if MARKUP_RE.search(value):
        raise ValidationError(f"'{field}' must not contain '<' or '>' characters")
    return value


def validate_choice(value, field, choices):
    """Accepts any capitalisation and returns the official spelling ('high' -> 'High')."""
    if not isinstance(value, str):
        raise ValidationError(f"'{field}' must be a string")
    lookup = {c.lower(): c for c in choices}
    canonical = lookup.get(value.strip().lower())
    if canonical is None:
        raise ValidationError(f"Invalid {field}. Allowed values: {', '.join(choices)}")
    return canonical


def validate_full_name(value):
    value = clean_text(value, "full_name", 2, 100)
    if not NAME_RE.match(value):
        raise ValidationError("'full_name' may only contain letters, spaces, apostrophes, dots and hyphens")
    return value


def validate_username(value):
    if not isinstance(value, str) or not USERNAME_RE.match(value.strip()):
        raise ValidationError("'username' must be 3-30 characters: letters, digits, '_', '.', '-'")
    return value.strip()


def validate_email(value):
    if not isinstance(value, str):
        raise ValidationError("'email' must be a string")
    value = value.strip().lower()
    if len(value) > 254 or not EMAIL_RE.match(value):
        raise ValidationError("Invalid email format")
    return value


PASSWORD_RULES = ("at least 8 characters (max 72 bytes), one uppercase letter, one lowercase "
                  "letter, one digit, one special character, and must not contain the username")


def validate_password(password, username=""):
    if not isinstance(password, str):
        raise ValidationError("'password' must be a string")
    problems = []
    if len(password) < 8:
        problems.append("at least 8 characters")
    if len(password.encode("utf-8")) > 72:   # bcrypt only uses the first 72 bytes
        problems.append("at most 72 bytes")
    if not re.search(r"[A-Z]", password):
        problems.append("an uppercase letter")
    if not re.search(r"[a-z]", password):
        problems.append("a lowercase letter")
    if not re.search(r"\d", password):
        problems.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        problems.append("a special character")
    if username and username.lower() in password.lower():
        problems.append("must not contain the username")
    if problems:
        raise ValidationError("Password does not meet requirements", {"password_requirements": problems})
    return password


def parse_positive_int(value, field):
    """IDs coming from the URL, query string or body must be positive integers."""
    if isinstance(value, bool):
        raise ValidationError(f"'{field}' must be a positive integer")
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValidationError(f"'{field}' must be a positive integer")
    if number <= 0 or number > 2**63 - 1:
        raise ValidationError(f"'{field}' must be a positive integer")
    return number


def validate_date(value, field):
    try:
        return datetime.strptime(value.strip(), DATE_FMT).strftime(DATE_FMT)
    except (ValueError, AttributeError):
        raise ValidationError(f"'{field}' must be a date in YYYY-MM-DD format")


def pagination(args, default_limit=100, max_limit=500):
    limit = args.get("limit", default_limit)
    offset = args.get("offset", 0)
    try:
        limit, offset = int(limit), int(offset)
    except (TypeError, ValueError):
        raise ValidationError("'limit' and 'offset' must be integers")
    if not 1 <= limit <= max_limit or offset < 0:
        raise ValidationError(f"'limit' must be 1-{max_limit} and 'offset' must be >= 0")
    return limit, offset


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
