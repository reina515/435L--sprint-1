"""
Authentication (who are you?) and authorization (are you allowed?).

Mechanism: JSON Web Tokens (JWT, HS256)
  1. POST /users/login checks username/email + bcrypt password and returns a token
     signed with JWT_SECRET. It contains user_id, username, role, a unique id (jti)
     and an expiry time (exp).
  2. The client sends it on every request:   Authorization: Bearer <token>
  3. Every service verifies the signature and expiry, checks the token was not
     revoked by logout, and RE-LOADS the user from the database so a deleted,
     suspended or re-roled user is handled immediately (the role in the database
     wins over the role written in the token).
  4. The role is checked against the RBAC matrix in shared/permissions.py.
     Rejections return 401/403 and are recorded in the audit log.
"""
import hmac
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import g, request

from shared.audit_client import log_event
from shared.config import JWT_ALGORITHM, JWT_EXPIRES_MINUTES, JWT_SECRET, SERVICE_API_KEY
from shared.db import get_db
from shared.errors import forbidden, unauthorized
from shared.permissions import OWN, scope_for
from shared.service_client import SERVICE_KEY_HEADER


# ---------------------------------------------------------------- tokens
def create_token(user):
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=JWT_EXPIRES_MINUTES)
    claims = {
        "sub": str(user["user_id"]),
        "username": user["username"],
        "role": user["role"],
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": expires,
    }
    token = jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, expires.strftime("%Y-%m-%d %H:%M:%S")


def decode_token(token):
    # algorithms=[...] is pinned so a forged token using "none" is refused
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                      options={"require": ["exp", "sub", "jti"]})


def revoke_token(claims):
    expires = datetime.fromtimestamp(claims["exp"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    try:
        conn.execute("DELETE FROM revoked_tokens WHERE expires_at < strftime('%Y-%m-%d %H:%M:%S','now')")
        conn.execute("INSERT OR IGNORE INTO revoked_tokens (jti, user_id, expires_at) VALUES (?, ?, ?)",
                     (claims["jti"], int(claims["sub"]), expires))
        conn.commit()
    finally:
        conn.close()


def _is_revoked(jti):
    conn = get_db()
    try:
        return conn.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)).fetchone() is not None
    finally:
        conn.close()


def _load_user(user_id):
    conn = get_db()
    try:
        row = conn.execute("SELECT user_id, username, role, account_status FROM users WHERE user_id = ?",
                           (user_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _bearer_token():
    header = request.headers.get("Authorization", "")
    if not header:
        return None
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1]


# ---------------------------------------------------------------- authentication
def authenticate():
    """Returns (user, None) on success or (None, error_response) on failure."""
    token = _bearer_token()
    if token is None:
        _log_auth_failure(None, "Missing Authorization header")
        return None, unauthorized("Authentication required: send 'Authorization: Bearer <token>'")
    if token == "":
        _log_auth_failure(None, "Malformed Authorization header")
        return None, unauthorized("Malformed Authorization header, expected 'Bearer <token>'")
    try:
        claims = decode_token(token)
    except jwt.ExpiredSignatureError:
        _log_auth_failure(None, "Expired token")
        return None, unauthorized("Token has expired, please log in again")
    except jwt.InvalidTokenError:
        _log_auth_failure(None, "Invalid token")
        return None, unauthorized("Invalid authentication token")

    if _is_revoked(claims["jti"]):
        _log_auth_failure(int(claims["sub"]), "Revoked (logged-out) token used")
        return None, unauthorized("Token has been revoked, please log in again")

    user = _load_user(int(claims["sub"]))
    if user is None:
        _log_auth_failure(None, f"Token of deleted user id {claims['sub']} used")
        return None, unauthorized("User account no longer exists")
    if user["account_status"] != "Active":
        _log_auth_failure(user["user_id"], f"{user['account_status']} account tried to access the API")
        return None, forbidden(f"Account is {user['account_status'].lower()}")

    user["token_claims"] = claims
    return user, None


def _log_auth_failure(user_id, reason):
    log_event(user_id=user_id, action="UNAUTHENTICATED_ACCESS",
              description=f"{reason} on {request.method} {request.path} from {request.remote_addr}",
              severity="Warning")


def get_optional_user():
    """For endpoints open to anonymous users (registration).
    No header -> (None, None).  Header present -> must be valid."""
    if request.headers.get("Authorization") is None:
        return None, None
    return authenticate()


def is_service_request():
    key = request.headers.get(SERVICE_KEY_HEADER)
    return bool(key) and hmac.compare_digest(key, SERVICE_API_KEY)


# ---------------------------------------------------------------- authorization
def deny(permission, user=None, reason=None):
    """Reject with 403 AND record the permission violation in the audit log."""
    user = user or g.get("current_user")
    text = reason or f"attempted {request.method} {request.path} without permission '{permission}'"
    log_event(user_id=user["user_id"] if user else None, action="UNAUTHORIZED_ACCESS",
              description=f"{user['username'] if user else 'anonymous'} "
                          f"({user['role'] if user else '-'}) {text}",
              severity="Warning")
    return forbidden()


def require_permission(permission, allow_service=False):
    """Decorator: authenticate the caller and check the RBAC matrix.

    Sets g.current_user (dict) and g.scope ("all" / "own").
    With allow_service=True, a trusted internal service (X-Service-Key) is also accepted;
    then g.current_user is None and g.is_service is True.
    """
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            g.is_service = False
            if allow_service and is_service_request():
                g.is_service, g.current_user, g.scope = True, None, "all"
                return view(*args, **kwargs)

            user, error = authenticate()
            if error:
                return error
            g.current_user = user
            scope = scope_for(user["role"], permission)
            if scope is None:
                return deny(permission, user)
            g.scope = scope
            return view(*args, **kwargs)
        return wrapper
    return decorator


def require_service_key(view):
    """Decorator for /internal/* endpoints: only other services may call them."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not is_service_request():
            log_event(user_id=None, action="UNAUTHORIZED_ACCESS",
                      description=f"Internal endpoint {request.path} called without a valid service key "
                                  f"from {request.remote_addr}", severity="Warning")
            return forbidden("This endpoint is reserved for internal services")
        return view(*args, **kwargs)
    return wrapper


def owns_or_all(owner_id):
    """True if the caller's scope is ALL, or OWN and the record belongs to them."""
    if g.get("is_service") or g.scope != OWN:
        return True
    return g.current_user["user_id"] == owner_id
