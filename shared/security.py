import hashlib
import hmac
import re
from datetime import datetime, timezone

import bcrypt
from cryptography.fernet import Fernet, InvalidToken

from shared.config import FERNET_KEY, HMAC_KEY
from shared.errors import ValidationError


class PasswordHasher:
    ROUNDS = 12

    # hashes the password with bcrypt so the real password is never stored
    @staticmethod
    def hash(plain_password):
        return bcrypt.hashpw(plain_password.encode("utf-8"),
                             bcrypt.gensalt(rounds=PasswordHasher.ROUNDS)).decode("utf-8")

    # compares a typed password with the saved hash
    @staticmethod
    def verify(plain_password, password_hash):
        try:
            return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
        except (ValueError, TypeError):
            return False


DUMMY_PASSWORD_HASH = PasswordHasher.hash("timing-attack-protection-dummy")


class CryptoManager:
    # prepares the fernet cipher and the hmac key
    def __init__(self, fernet_key, hmac_key):
        self._cipher = Fernet(fernet_key.encode() if isinstance(fernet_key, str) else fernet_key)
        self._hmac_key = hmac_key.encode()

    # encrypts text before it goes in the database
    def encrypt(self, plain_text):
        if plain_text is None:
            return None
        return self._cipher.encrypt(plain_text.encode("utf-8")).decode("utf-8")

    # decrypts it back, and if it fails it returns a message instead of crashing
    def decrypt(self, token):
        if token is None:
            return None
        try:
            return self._cipher.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            return "[unable to decrypt]"

    # hash of the email so i can search by email even though it is encrypted
    def blind_index(self, value):
        return hmac.new(self._hmac_key, value.strip().lower().encode("utf-8"),
                        hashlib.sha256).hexdigest()

    # makes an hmac signature from the log values to detect if someone edits a log
    def sign(self, *parts):
        message = "\x1f".join("" if p is None else str(p) for p in parts)
        return hmac.new(self._hmac_key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    # true if the saved signature still matches the values
    def verify_signature(self, signature, *parts):
        return hmac.compare_digest(signature or "", self.sign(*parts))


crypto = CryptoManager(FERNET_KEY, HMAC_KEY)


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


# the body has to be a json object and it cannot be empty
def require_json_object(data):
    if data is None:
        raise ValidationError("Request body must be valid JSON (Content-Type: application/json)")
    if not isinstance(data, dict):
        raise ValidationError("Request body must be a JSON object")
    if not data:
        raise ValidationError("Request body cannot be empty")
    return data


# if the body has any field i do not expect, the request is refused
def reject_unknown_fields(data, allowed):
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        raise ValidationError(f"Unexpected field(s): {', '.join(unknown)}",
                              {"allowed_fields": sorted(allowed)})


# makes sure none of the required fields are missing or blank
def require_fields(data, fields):
    missing = [f for f in fields
               if data.get(f) is None or (isinstance(data.get(f), str) and not data[f].strip())]
    if missing:
        raise ValidationError(f"Missing required field(s): {', '.join(missing)}")


# trims the text, checks its length and refuses control characters and html tags
def clean_text(value, field, min_len=1, max_len=255, multiline=False):
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


# checks the value is one of the allowed options and fixes the capital letters
def validate_choice(value, field, choices):
    if not isinstance(value, str):
        raise ValidationError(f"'{field}' must be a string")
    lookup = {c.lower(): c for c in choices}
    canonical = lookup.get(value.strip().lower())
    if canonical is None:
        raise ValidationError(f"Invalid {field}. Allowed values: {', '.join(choices)}")
    return canonical


# a name can only have letters, spaces, apostrophes, dots and hyphens
def validate_full_name(value):
    value = clean_text(value, "full_name", 2, 100)
    if not NAME_RE.match(value):
        raise ValidationError("'full_name' may only contain letters, spaces, apostrophes, dots and hyphens")
    return value


# usernames must be 3 to 30 letters, digits, underscores or dots
def validate_username(value):
    if not isinstance(value, str) or not USERNAME_RE.match(value.strip()):
        raise ValidationError("'username' must be 3-30 characters: letters, digits, '_', '.', '-'")
    return value.strip()


# lowercases the email and checks it looks like a real email
def validate_email(value):
    if not isinstance(value, str):
        raise ValidationError("'email' must be a string")
    value = value.strip().lower()
    if len(value) > 254 or not EMAIL_RE.match(value):
        raise ValidationError("Invalid email format")
    return value


PASSWORD_RULES = ("at least 8 characters (max 72 bytes), one uppercase letter, one lowercase "
                  "letter, one digit, one special character, and must not contain the username")


# password rules: 8 characters, upper and lower case, a digit, a symbol and not the username
def validate_password(password, username=""):
    if not isinstance(password, str):
        raise ValidationError("'password' must be a string")
    problems = []
    if len(password) < 8:
        problems.append("at least 8 characters")
    if len(password.encode("utf-8")) > 72:
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


# turns ids from the url or body into positive integers or raises an error
def parse_positive_int(value, field):
    if isinstance(value, bool):
        raise ValidationError(f"'{field}' must be a positive integer")
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValidationError(f"'{field}' must be a positive integer")
    if number <= 0 or number > 2**63 - 1:
        raise ValidationError(f"'{field}' must be a positive integer")
    return number


# accepts only dates written as year month day
def validate_date(value, field):
    try:
        return datetime.strptime(value.strip(), DATE_FMT).strftime(DATE_FMT)
    except (ValueError, AttributeError):
        raise ValidationError(f"'{field}' must be a date in YYYY-MM-DD format")


# reads limit and offset from the query and checks they are in range
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


# current utc time as text, used for all the dates i save
def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
