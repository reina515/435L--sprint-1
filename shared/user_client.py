"""
Client for the internal endpoints of the Users and Identity Management Service.
Used by the Notification service (does this user exist?) and the Audit service
(who are the administrators to alert?).
"""
from shared.config import USER_SERVICE_URL
from shared.service_client import ServiceClient

_client = ServiceClient(USER_SERVICE_URL)


class UserServiceUnavailable(Exception):
    pass


def get_user(user_id):
    """Return the user dict, or None if it does not exist.
    Raises UserServiceUnavailable if the Users service cannot be reached."""
    status, body = _client.get(f"/internal/users/{int(user_id)}")
    if status == 200:
        return body.get("data")
    if status == 404:
        return None
    raise UserServiceUnavailable("Users service is unavailable")


def get_users_by_role(role):
    status, body = _client.get("/internal/users", params={"role": role, "status": "Active"})
    if status == 200:
        return body.get("data", [])
    raise UserServiceUnavailable("Users service is unavailable")
