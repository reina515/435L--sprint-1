from flask import Blueprint, g, request

from shared.audit_client import log_event
from shared.auth import deny, owns_or_all, require_permission
from shared.errors import ValidationError, not_found, service_unavailable, success
from shared.permissions import OWN
from shared.security import (NOTIFICATION_SEVERITIES, NOTIFICATION_STATUSES, NOTIFICATION_TYPES,
                             clean_text, pagination, parse_positive_int, reject_unknown_fields,
                             require_fields, require_json_object, validate_choice)
from shared.user_client import UserServiceUnavailable, get_user
from notification_service.repository import NotificationRepository

bp = Blueprint("notifications", __name__)
repo = NotificationRepository()

CREATE_FIELDS = ["user_id", "title", "message", "notification_type", "severity"]
SEARCH_PARAMS = ["user", "user_id", "type", "notification_type", "severity", "status", "limit", "offset"]


# who to put in the audit log, None when the call came from another service
def _actor():
    return None if g.get("is_service") else g.current_user["user_id"]


# POST /notifications creates a notification after asking the users service if the user exists
@bp.route("/notifications", methods=["POST"])
@require_permission("notifications:create", allow_service=True)
def create_notification():
    data = require_json_object(request.get_json(silent=True))
    reject_unknown_fields(data, CREATE_FIELDS)
    require_fields(data, CREATE_FIELDS)
    user_id = parse_positive_int(data["user_id"], "user_id")
    title = clean_text(data["title"], "title", 3, 150)
    message = clean_text(data["message"], "message", 1, 2000, multiline=True)
    notification_type = validate_choice(data["notification_type"], "notification_type", NOTIFICATION_TYPES)
    severity = validate_choice(data["severity"], "severity", NOTIFICATION_SEVERITIES)

    try:
        recipient = get_user(user_id)
    except UserServiceUnavailable:
        return service_unavailable("Users service is unavailable, cannot verify the recipient")
    if recipient is None:
        return not_found(f"User with id {user_id} not found")

    notification_id = repo.create(user_id, title, message, notification_type, severity)
    who = "system service" if g.is_service else f"'{g.current_user['username']}'"
    log_event(user_id=_actor(), action="NOTIFICATION_CREATED",
              description=f"{notification_type} notification #{notification_id} ({severity}) "
                          f"created for '{recipient['username']}' by {who}",
              severity="Information")
    return success("Notification created successfully", repo.get_by_id(notification_id).to_dict(), 201)


# GET /notifications/user/{user_id} lists a user's notifications with the unread count
@bp.route("/notifications/user/<user_id>", methods=["GET"])
@require_permission("notifications:by_user")
def get_user_notifications(user_id):
    user_id = parse_positive_int(user_id, "user_id")
    if not owns_or_all(user_id):
        return deny("notifications:by_user", reason=f"tried to read the notifications of user {user_id}")

    filters = {"user_id": user_id}
    if request.args.get("status"):
        filters["status"] = validate_choice(request.args["status"], "status", NOTIFICATION_STATUSES)
    limit, offset = pagination(request.args)
    notifications, total = repo.search(filters, limit, offset)

    if not notifications and user_id != g.current_user["user_id"]:
        try:
            if get_user(user_id) is None:
                return not_found(f"User with id {user_id} not found")
        except UserServiceUnavailable:
            pass
    message = (f"Notifications for user {user_id} retrieved successfully" if notifications
               else f"User {user_id} has no notifications")
    return success(message, [n.to_dict() for n in notifications], user_id=user_id,
                   count=len(notifications), total=total, unread=repo.unread_count(user_id))


# GET /notifications/search filters notifications, analysts only see their own
@bp.route("/notifications/search", methods=["GET"])
@require_permission("notifications:search")
def search_notifications():
    args = request.args
    unknown = sorted(set(args) - set(SEARCH_PARAMS))
    if unknown:
        raise ValidationError(f"Unknown search parameter(s): {', '.join(unknown)}",
                              {"allowed_parameters": SEARCH_PARAMS})
    filters = {}
    user = args.get("user_id") or args.get("user")
    if user:
        filters["user_id"] = parse_positive_int(user, "user_id")
    ntype = args.get("notification_type") or args.get("type")
    if ntype:
        filters["notification_type"] = validate_choice(ntype, "notification_type", NOTIFICATION_TYPES)
    if args.get("severity"):
        filters["severity"] = validate_choice(args["severity"], "severity", NOTIFICATION_SEVERITIES)
    if args.get("status"):
        filters["status"] = validate_choice(args["status"], "status", NOTIFICATION_STATUSES)

    if g.scope == OWN:
        own_id = g.current_user["user_id"]
        if filters.get("user_id", own_id) != own_id:
            return deny("notifications:search",
                        reason=f"tried to search the notifications of user {filters['user_id']}")
        filters["user_id"] = own_id

    limit, offset = pagination(args)
    notifications, total = repo.search(filters, limit, offset)
    message = ("Notifications retrieved successfully" if notifications
               else "No notifications match the search criteria")
    return success(message, [n.to_dict() for n in notifications],
                   count=len(notifications), total=total, filters=filters)


# GET /notifications/{id} returns one notification if you are allowed to see it
@bp.route("/notifications/<notification_id>", methods=["GET"])
@require_permission("notifications:view")
def get_notification(notification_id):
    notification_id = parse_positive_int(notification_id, "id")
    notification = repo.get_by_id(notification_id)
    if notification is None:
        return not_found(f"Notification with id {notification_id} not found")
    if not owns_or_all(notification.user_id):
        return deny("notifications:view", reason=f"tried to read notification #{notification_id} "
                                                 f"of user {notification.user_id}")
    return success("Notification retrieved successfully", notification.to_dict())


# PUT /notifications/{id}/read marks a notification as read
@bp.route("/notifications/<notification_id>/read", methods=["PUT"])
@require_permission("notifications:mark_read")
def mark_notification_read(notification_id):
    notification_id = parse_positive_int(notification_id, "id")
    notification = repo.get_by_id(notification_id)
    if notification is None:
        return not_found(f"Notification with id {notification_id} not found")
    if not owns_or_all(notification.user_id):
        return deny("notifications:mark_read", reason=f"tried to mark notification #{notification_id} "
                                                      f"of user {notification.user_id} as read")
    if notification.is_read:
        return success("Notification was already marked as read", notification.to_dict(),
                       previous_status="Read")

    repo.mark_read(notification_id)
    me = g.current_user
    log_event(user_id=me["user_id"], action="NOTIFICATION_READ",
              description=f"'{me['username']}' marked notification #{notification_id} as read",
              severity="Information")
    return success("Notification marked as read", repo.get_by_id(notification_id).to_dict(),
                   previous_status="Unread")


# DELETE /notifications/{id} admins only
@bp.route("/notifications/<notification_id>", methods=["DELETE"])
@require_permission("notifications:delete")
def delete_notification(notification_id):
    notification_id = parse_positive_int(notification_id, "id")
    notification = repo.get_by_id(notification_id)
    if notification is None:
        return not_found(f"Notification with id {notification_id} not found")
    repo.delete(notification_id)
    me = g.current_user
    log_event(user_id=me["user_id"], action="NOTIFICATION_DELETED",
              description=f"Administrator '{me['username']}' deleted notification #{notification_id} "
                          f"('{notification.title}') of user {notification.user_id}", severity="Warning")
    return success("Notification deleted successfully", {"notification_id": notification_id})
