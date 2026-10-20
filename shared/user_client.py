from shared.config import ROUTE_PREFIX, USER_SERVICE_URL
from shared.service_client import ServiceClient

_client = ServiceClient(USER_SERVICE_URL)


class UserServiceUnavailable(Exception):
    pass


# asks the users service for one user, None means the user does not exist
def get_user(user_id):
    status, body = _client.get(f"{ROUTE_PREFIX}/internal/users/{int(user_id)}")
    if status == 200:
        return body.get("data")
    if status == 404:
        return None
    raise UserServiceUnavailable("Users service is unavailable")


# gets all the active users that have a certain role, i use it to find the admins
def get_users_by_role(role):
    status, body = _client.get(f"{ROUTE_PREFIX}/internal/users", params={"role": role, "status": "Active"})
    if status == 200:
        return body.get("data", [])
    raise UserServiceUnavailable("Users service is unavailable")
