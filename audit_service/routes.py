import logging
import re
import threading

from flask import Blueprint, g, request

from shared.audit_client import log_event
from shared.auth import require_permission
from shared.errors import ValidationError, not_found, success
from shared.notification_client import notify
from shared.permissions import ADMIN
from shared.security import (LOG_SEVERITIES, SERVICES, clean_text, pagination, parse_positive_int,
                             reject_unknown_fields, require_fields, require_json_object,
                             validate_choice, validate_date, validate_username)
from shared.user_client import UserServiceUnavailable, get_users_by_role
from audit_service.repository import AuditLogRepository

bp = Blueprint("logs", __name__)
repo = AuditLogRepository()
log = logging.getLogger("audit_service")

ACTION_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,49}$")
CREATE_FIELDS = ["user_id", "action", "description", "severity", "related_service"]
SEARCH_PARAMS = ["user", "user_id", "action", "severity", "service", "related_service",
                 "date", "date_from", "date_to", "limit", "offset"]


# turns an action like login failed into LOGIN_FAILED and checks it is valid
def normalize_action(value):
    if not isinstance(value, str):
        raise ValidationError("'action' must be a string")
    value = re.sub(r"[\s\-]+", "_", value.strip()).upper()
    if not ACTION_RE.match(value):
        raise ValidationError("'action' must be 3-50 characters: letters, digits and '_' "
                              "(example: INCIDENT_CREATED)")
    return value


# saves the log and if it is Critical it alerts the admins in the background
def store_log(user_id, action, description, severity, related_service):
    log_id = repo.create(user_id, action, description, severity, related_service)
    if severity == "Critical":
        threading.Thread(target=_alert_admins, args=(log_id, action, description, related_service),
                         daemon=True).start()
    return log_id


# sends a critical notification to every active admin
def _alert_admins(log_id, action, description, related_service):
    try:
        for admin in get_users_by_role(ADMIN):
            notify(admin["user_id"], f"Critical security event: {action}",
                   f"[{related_service}] {description} (audit log #{log_id})", "Security Alert", "Critical")
    except UserServiceUnavailable:
        log.error("Could not alert administrators about critical log #%s: Users service down", log_id)


# lets the audit service save its own logs without calling itself over http
def local_writer(user_id, action, description, severity, related_service):
    store_log(user_id, normalize_action(action), description, severity, related_service)


# POST /logs creates a log record, for admins or other services
@bp.route("/logs", methods=["POST"])
@require_permission("logs:create", allow_service=True)
def create_log():
    data = require_json_object(request.get_json(silent=True))
    reject_unknown_fields(data, CREATE_FIELDS)
    required = ["action", "description", "severity", "related_service"]
    if not g.is_service:
        required.insert(0, "user_id")
    elif "user_id" not in data:
        raise ValidationError("Missing required field(s): user_id (use null for system events)")
    require_fields(data, required)

    user_id = None
    if data.get("user_id") is not None:
        user_id = parse_positive_int(data["user_id"], "user_id")
        if not g.is_service and not repo.user_exists(user_id):
            raise ValidationError(f"User with id {user_id} does not exist")
    action = normalize_action(data["action"])
    description = clean_text(data["description"], "description", 3, 1000, multiline=True)
    severity = validate_choice(data["severity"], "severity", LOG_SEVERITIES)
    related_service = validate_choice(data["related_service"], "related_service", SERVICES)

    log_id = store_log(user_id, action, description, severity, related_service)
    return success("Log record created successfully", repo.get_by_id(log_id).to_dict(), 201)


# GET /logs lists all logs for admins and auditors
@bp.route("/logs", methods=["GET"])
@require_permission("logs:list")
def get_all_logs():
    limit, offset = pagination(request.args)
    logs = repo.list_all(limit, offset)
    return success("Logs retrieved successfully", [entry.to_dict() for entry in logs],
                   count=len(logs), total=repo.count(), limit=limit, offset=offset)


# GET /logs/search filters logs by user, action, severity, service or date
@bp.route("/logs/search", methods=["GET"])
@require_permission("logs:search")
def search_logs():
    args = request.args
    unknown = sorted(set(args) - set(SEARCH_PARAMS))
    if unknown:
        raise ValidationError(f"Unknown search parameter(s): {', '.join(unknown)}",
                              {"allowed_parameters": SEARCH_PARAMS})
    filters = {}
    user = args.get("user_id") or args.get("user")
    if user:
        if user.strip().isdigit():
            filters["user_id"] = parse_positive_int(user, "user")
        else:
            filters["username"] = validate_username(user)
    if args.get("action"):
        filters["action"] = re.sub(r"[\s\-]+", "_", clean_text(args["action"], "action", 1, 50)).upper()
    if args.get("severity"):
        filters["severity"] = validate_choice(args["severity"], "severity", LOG_SEVERITIES)
    service = args.get("related_service") or args.get("service")
    if service:
        filters["related_service"] = validate_choice(service, "service", SERVICES)
    for key in ("date", "date_from", "date_to"):
        if args.get(key):
            filters[key] = validate_date(args[key], key)
    if not filters:
        raise ValidationError("Provide at least one search criterion: user, action, severity, "
                              "service, date, date_from or date_to")

    limit, offset = pagination(args)
    logs, total = repo.search(filters, limit, offset)
    message = "Logs retrieved successfully" if logs else "No logs match the search criteria"
    return success(message, [entry.to_dict() for entry in logs],
                   count=len(logs), total=total, filters=filters)


# GET /logs/user/{user_id} shows everything one user did
@bp.route("/logs/user/<user_id>", methods=["GET"])
@require_permission("logs:by_user")
def get_logs_by_user(user_id):
    user_id = parse_positive_int(user_id, "user_id")
    limit, offset = pagination(request.args)
    logs, total = repo.by_user(user_id, limit, offset)
    message = (f"Logs for user {user_id} retrieved successfully" if logs
               else f"No logs found for user {user_id}")
    return success(message, [entry.to_dict() for entry in logs], user_id=user_id,
                   user_exists=repo.user_exists(user_id), count=len(logs), total=total)


# GET /logs/{id} returns a single log or 404
@bp.route("/logs/<log_id>", methods=["GET"])
@require_permission("logs:view")
def get_log(log_id):
    log_id = parse_positive_int(log_id, "id")
    entry = repo.get_by_id(log_id)
    if entry is None:
        return not_found(f"Log with id {log_id} not found")
    return success("Log retrieved successfully", entry.to_dict())


# DELETE /logs/{id} only admins can delete, and the delete itself gets logged
@bp.route("/logs/<log_id>", methods=["DELETE"])
@require_permission("logs:delete")
def delete_log(log_id):
    log_id = parse_positive_int(log_id, "id")
    entry = repo.get_by_id(log_id)
    if entry is None:
        return not_found(f"Log with id {log_id} not found")
    repo.delete(log_id)
    me = g.current_user
    log_event(user_id=me["user_id"], action="LOG_DELETED",
              description=f"Administrator '{me['username']}' deleted audit log #{log_id} "
                          f"(action {entry.action}, severity {entry.severity}, recorded {entry.timestamp})",
              severity="Warning")
    return success("Log deleted successfully", {"log_id": log_id})
