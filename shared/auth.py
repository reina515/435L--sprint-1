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


# makes a jwt for the user that expires after the time set in .env
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


# checks the token signature and expiry and gives back what is inside
def decode_token(token):
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                      options={"require": ["exp", "sub", "jti"]})


# on logout the token id is saved here so it cannot be used again
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


# was this token already logged out?
def _is_revoked(jti):
    conn = get_db()
    try:
        return conn.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)).fetchone() is not None
    finally:
        conn.close()


# reads the user again from the database so a deleted or suspended user is caught right away
def _load_user(user_id):
    conn = get_db()
    try:
        row = conn.execute("SELECT user_id, username, role, account_status FROM users WHERE user_id = ?",
                           (user_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# pulls the token out of the Authorization header
def _bearer_token():
    header = request.headers.get("Authorization", "")
    if not header:
        return None
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1]


# main login check for every protected route, gives back the user or an error
def authenticate():
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


# every failed authentication gets written in the audit logs as a warning
def _log_auth_failure(user_id, reason):
    log_event(user_id=user_id, action="UNAUTHENTICATED_ACCESS",
              description=f"{reason} on {request.method} {request.path} from {request.remote_addr}",
              severity="Warning")


# for register, where you can be logged in or not
def get_optional_user():
    if request.headers.get("Authorization") is None:
        return None, None
    return authenticate()


# true only if the request carries the right service key
def is_service_request():
    key = request.headers.get(SERVICE_KEY_HEADER)
    return bool(key) and hmac.compare_digest(key, SERVICE_API_KEY)


# refuses the request with 403 and saves the attempt in the audit logs
def deny(permission, user=None, reason=None):
    user = user or g.get("current_user")
    text = reason or f"attempted {request.method} {request.path} without permission '{permission}'"
    log_event(user_id=user["user_id"] if user else None, action="UNAUTHORIZED_ACCESS",
              description=f"{user['username'] if user else 'anonymous'} "
                          f"({user['role'] if user else '-'}) {text}",
              severity="Warning")
    return forbidden()


# decorator i put on routes to check the token and the role before the route runs
def require_permission(permission, allow_service=False):
    # wraps the route function
    def decorator(view):
        # this is what runs on each request, it checks the user and the permission then calls the route
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


# decorator for internal routes that only my other services are allowed to call
def require_service_key(view):
    # blocks the call with 403 if the service key is wrong
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not is_service_request():
            log_event(user_id=None, action="UNAUTHORIZED_ACCESS",
                      description=f"Internal endpoint {request.path} called without a valid service key "
                                  f"from {request.remote_addr}", severity="Warning")
            return forbidden("This endpoint is reserved for internal services")
        return view(*args, **kwargs)
    return wrapper


# checks if the user can see every record or if this record belongs to them
def owns_or_all(owner_id):
    if g.get("is_service") or g.scope != OWN:
        return True
    return g.current_user["user_id"] == owner_id
