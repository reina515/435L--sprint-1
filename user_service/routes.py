import sqlite3

from flask import Blueprint, g, request

from shared.audit_client import log_event
from shared.auth import (create_token, deny, get_optional_user, require_permission,
                         require_service_key, revoke_token)
from shared.config import MAX_FAILED_LOGINS
from shared.errors import (ValidationError, bad_request, conflict, error_response, not_found,
                           success, unauthorized)
from shared.notification_client import notify
from shared.permissions import ADMIN, EMPLOYEE, OWN, permissions_by_role
from shared.security import (ACCOUNT_STATUSES, DUMMY_PASSWORD_HASH, PASSWORD_RULES, ROLES,
                             PasswordHasher, clean_text, pagination, parse_positive_int,
                             reject_unknown_fields, require_fields, require_json_object,
                             validate_choice, validate_email, validate_full_name,
                             validate_password, validate_username)
from user_service.repository import UserRepository

bp = Blueprint("users", __name__)
repo = UserRepository()

REGISTER_REQUIRED = ["full_name", "username", "email", "password", "department", "role"]
REGISTER_OPTIONAL = ["account_status"]
UPDATE_SELF_FIELDS = ["full_name", "email", "department"]
UPDATE_ADMIN_FIELDS = UPDATE_SELF_FIELDS + ["role", "account_status"]


# POST /users/register creates a new account after validating everything, only admins can create privileged roles
@bp.route("/users/register", methods=["POST"])
def register():
    caller, error = get_optional_user()
    if error:
        return error
    if caller and caller["role"] not in (ADMIN, EMPLOYEE):
        return deny("users:register", caller)

    data = require_json_object(request.get_json(silent=True))
    reject_unknown_fields(data, REGISTER_REQUIRED + REGISTER_OPTIONAL)
    require_fields(data, REGISTER_REQUIRED)

    full_name = validate_full_name(data["full_name"])
    username = validate_username(data["username"])
    email = validate_email(data["email"])
    validate_password(data["password"], username)
    department = clean_text(data["department"], "department", 2, 100)
    role = validate_choice(data["role"], "role", ROLES)
    is_admin = caller is not None and caller["role"] == ADMIN

    if role != EMPLOYEE and not is_admin:
        return deny("users:register", caller,
                    f"tried to register a '{role}' account; only administrators may assign this role")
    account_status = "Active"
    if "account_status" in data:
        if not is_admin:
            return deny("users:register", caller, "tried to set account_status during registration")
        account_status = validate_choice(data["account_status"], "account_status", ACCOUNT_STATUSES)

    if repo.get_by_username(username):
        return conflict(f"Username '{username}' is already taken")
    if repo.email_taken(email):
        return conflict("An account with this email already exists")

    try:
        new_id = repo.create(full_name, username, email, PasswordHasher.hash(data["password"]),
                             department, role, account_status)
    except sqlite3.IntegrityError:
        return conflict("Username or email already exists")

    actor = caller["user_id"] if caller else new_id
    log_event(user_id=actor, action="USER_CREATED",
              description=f"User '{username}' (id {new_id}) registered with role '{role}'"
                          + (f" by administrator '{caller['username']}'" if is_admin else " (self-registration)"),
              severity="Information")
    if role != EMPLOYEE:
        log_event(user_id=actor, action="ROLE_ASSIGNED",
                  description=f"Role '{role}' assigned to user '{username}' (id {new_id})", severity="Warning")
    notify(new_id, "Welcome to the Security Incident Response Platform",
           f"Hello {full_name}, your account '{username}' was created with the role '{role}'.",
           "System Notification", "Low")

    return success("User registered successfully", repo.get_by_id(new_id).to_dict(), 201)


# POST /users/login checks the username or email and the password and gives a token
@bp.route("/users/login", methods=["POST"])
def login():
    data = require_json_object(request.get_json(silent=True))
    reject_unknown_fields(data, ["username", "email", "password"])
    identifier = data.get("username") or data.get("email")
    if not identifier or not data.get("password"):
        raise ValidationError("Provide 'username' (or 'email') and 'password'")
    if not isinstance(identifier, str) or not isinstance(data["password"], str) or len(identifier) > 254:
        raise ValidationError("'username'/'email' and 'password' must be strings")
    identifier = identifier.strip()

    user = repo.get_by_email(identifier) if "@" in identifier else repo.get_by_username(identifier)

    if user is None:
        PasswordHasher.verify(data["password"], DUMMY_PASSWORD_HASH)
        log_event(user_id=None, action="LOGIN_FAILED",
                  description=f"Failed login: unknown username/email '{identifier[:60]}' "
                              f"from {request.remote_addr}", severity="Warning")
        return unauthorized("Invalid username/email or password")

    if not PasswordHasher.verify(data["password"], user.password_hash):
        attempts = repo.record_failed_login(user.user_id)
        log_event(user_id=user.user_id, action="LOGIN_FAILED",
                  description=f"Failed login for '{user.username}': wrong password "
                              f"(attempt {attempts}) from {request.remote_addr}", severity="Warning")
        if attempts % MAX_FAILED_LOGINS == 0:
            log_event(user_id=user.user_id, action="BRUTE_FORCE_SUSPECTED",
                      description=f"{attempts} consecutive failed logins for '{user.username}' "
                                  f"from {request.remote_addr}", severity="Critical")
            notify(user.user_id, "Suspicious login activity",
                   f"There were {attempts} failed login attempts on your account. "
                   f"If this was not you, contact a security administrator.", "Security Alert", "High")
        return unauthorized("Invalid username/email or password")

    if not user.is_active:
        log_event(user_id=user.user_id, action="LOGIN_BLOCKED",
                  description=f"Login refused for '{user.username}': account is {user.account_status}",
                  severity="Warning")
        return error_response(f"Account is {user.account_status.lower()}. "
                              f"Contact a security administrator.", 403)

    repo.record_successful_login(user.user_id)
    user = repo.get_by_id(user.user_id)
    token, expires_at = create_token(user.to_dict())
    log_event(user_id=user.user_id, action="LOGIN_SUCCESS",
              description=f"User '{user.username}' logged in from {request.remote_addr}",
              severity="Information")
    return success("Authentication successful", {
        "token": token, "token_type": "Bearer", "expires_at": expires_at, "user": user.to_dict(),
    })


# POST /users/logout revokes the current token
@bp.route("/users/logout", methods=["POST"])
@require_permission("users:logout")
def logout():
    revoke_token(g.current_user["token_claims"])
    log_event(user_id=g.current_user["user_id"], action="LOGOUT",
              description=f"User '{g.current_user['username']}' logged out (token revoked)",
              severity="Information")
    return success("Logged out successfully, the token can no longer be used")


# GET /users returns every user, for admins and auditors
@bp.route("/users", methods=["GET"])
@require_permission("users:list")
def get_all_users():
    limit, offset = pagination(request.args)
    users = repo.list_all(limit, offset)
    return success("Users retrieved successfully", [u.to_dict() for u in users],
                   count=len(users), total=repo.count(), limit=limit, offset=offset)


# GET /users/{username} returns one user, employees can only look at themselves
@bp.route("/users/<username>", methods=["GET"])
@require_permission("users:view")
def get_user_by_username(username):
    username = validate_username(username)
    if g.scope == OWN and username.lower() != g.current_user["username"].lower():
        return deny("users:view", reason=f"tried to view the profile of '{username}'")
    user = repo.get_by_username(username)
    if user is None:
        return not_found(f"User '{username}' not found")
    return success("User retrieved successfully", user.to_dict())


# PUT /users/{id} updates name, email and department, and admins can also change role and status
@bp.route("/users/<user_id>", methods=["PUT"])
@require_permission("users:update")
def update_user(user_id):
    user_id = parse_positive_int(user_id, "id")
    me = g.current_user
    if g.scope == OWN and user_id != me["user_id"]:
        return deny("users:update", reason=f"tried to update user id {user_id}")

    data = require_json_object(request.get_json(silent=True))
    is_admin = me["role"] == ADMIN
    if not is_admin and ({"role", "account_status"} & set(data)):
        return deny("users:change_role", reason="tried to change their own role/account status")
    reject_unknown_fields(data, UPDATE_ADMIN_FIELDS if is_admin else UPDATE_SELF_FIELDS)

    target = repo.get_by_id(user_id)
    if target is None:
        return not_found(f"User with id {user_id} not found")

    changes = {}
    if "full_name" in data:
        changes["full_name"] = validate_full_name(data["full_name"])
    if "department" in data:
        changes["department"] = clean_text(data["department"], "department", 2, 100)
    if "email" in data:
        changes["email"] = validate_email(data["email"])
        if repo.email_taken(changes["email"], exclude_user_id=user_id):
            return conflict("An account with this email already exists")
    if "role" in data:
        changes["role"] = validate_choice(data["role"], "role", ROLES)
    if "account_status" in data:
        changes["account_status"] = validate_choice(data["account_status"], "account_status",
                                                    ACCOUNT_STATUSES)
    if user_id == me["user_id"] and (
            changes.get("role", target.role) != target.role
            or changes.get("account_status", target.account_status) != target.account_status):
        return bad_request("Administrators cannot change their own role or account status "
                           "(prevents locking the platform out of its last administrator)")

    old = target.to_dict()
    changes = {k: v for k, v in changes.items() if old.get(k) != v}
    if not changes:
        return success("No changes were needed, the user already has these values", target.to_dict())

    try:
        repo.update(user_id, changes)
    except sqlite3.IntegrityError:
        return conflict("An account with this email already exists")

    log_event(user_id=me["user_id"], action="USER_UPDATED",
              description=f"'{me['username']}' updated user '{target.username}' (id {user_id}); "
                          f"fields changed: {', '.join(sorted(changes))}", severity="Information")
    if "role" in changes:
        log_event(user_id=me["user_id"], action="ROLE_CHANGED",
                  description=f"Role of '{target.username}' changed from '{target.role}' to "
                              f"'{changes['role']}' by '{me['username']}'", severity="Warning")
        notify(user_id, "Your role was changed",
               f"Your role changed from '{target.role}' to '{changes['role']}'.",
               "System Notification", "Medium")
    if "account_status" in changes:
        log_event(user_id=me["user_id"], action="ACCOUNT_STATUS_CHANGED",
                  description=f"Account status of '{target.username}' changed from "
                              f"'{target.account_status}' to '{changes['account_status']}'",
                  severity="Warning")
        notify(user_id, "Your account status was changed",
               f"Your account status is now '{changes['account_status']}'.",
               "System Notification", "High")

    return success("User updated successfully", repo.get_by_id(user_id).to_dict())


# DELETE /users/{id} lets an admin delete an account but not their own
@bp.route("/users/<user_id>", methods=["DELETE"])
@require_permission("users:delete")
def delete_user(user_id):
    user_id = parse_positive_int(user_id, "id")
    me = g.current_user
    if user_id == me["user_id"]:
        return bad_request("Administrators cannot delete their own account")
    target = repo.get_by_id(user_id)
    if target is None:
        return not_found(f"User with id {user_id} not found")

    repo.delete(user_id)
    log_event(user_id=me["user_id"], action="USER_DELETED",
              description=f"User '{target.username}' (id {user_id}, role '{target.role}') deleted by "
                          f"'{me['username']}'", severity="Warning")
    return success("User deleted successfully",
                   {"user_id": user_id, "username": target.username})


# GET /roles shows the roles, statuses, password rules and permissions
@bp.route("/roles", methods=["GET"])
@require_permission("roles:view")
def get_roles():
    return success("Roles and permissions retrieved successfully",
                   {"roles": list(ROLES), "account_statuses": list(ACCOUNT_STATUSES),
                    "password_policy": PASSWORD_RULES, "permissions": permissions_by_role()})


# internal route so other services can check that a user exists
@bp.route("/internal/users/<int:user_id>", methods=["GET"])
@require_service_key
def internal_get_user(user_id):
    user = repo.get_by_id(user_id)
    if user is None:
        return not_found(f"User with id {user_id} not found")
    return success("User found", user.to_public_dict())


# internal route that lists users by role or status for the other services
@bp.route("/internal/users", methods=["GET"])
@require_service_key
def internal_list_users():
    role = request.args.get("role")
    status = request.args.get("status")
    role = validate_choice(role, "role", ROLES) if role else None
    status = validate_choice(status, "status", ACCOUNT_STATUSES) if status else None
    users = repo.list_all(limit=1000, offset=0, role=role, status=status)
    return success("Users found", [u.to_public_dict() for u in users])
