"""
Service 9 - Security Playbook and Response Automation Service (port 5009)
Implemented by: Hayam Itani   (also sent in the X-Student-Name response header)

Endpoints
  POST   /playbooks                 create playbook          (Admin)
  GET    /playbooks                 list                     (Admin, Analyst, Auditor)
  GET    /playbooks/{id}            one, with ordered steps  (Admin, Analyst, Auditor)
  POST   /playbooks/{id}/actions    add response step        (Admin, Analyst)
  PUT    /actions/{id}/status       update a step            (Admin, Analyst)
  DELETE /playbooks/{id}            delete (+ its steps)     (Admin)

Audit logs written: PLAYBOOK_CREATED, RESPONSE_ACTION_ADDED, RESPONSE_ACTION_UPDATED (every step
  change, so each action's execution history is kept), PLAYBOOK_DELETED (Warning). Denied requests
  are logged as UNAUTHORIZED_ACCESS / UNAUTHENTICATED_ACCESS by shared/auth.py.
Notifications sent: "System Notification" to the user a response step is assigned to.
Calls to other services: Users (GET /internal/users/{id} to check the assigned user),
  Audit (POST /logs), Notifications (POST /notifications).

"""
import sqlite3

from flask import Blueprint, g, request

from shared.audit_client import log_event
from shared.auth import require_permission
from shared.errors import (ValidationError, bad_request, conflict, not_found, service_unavailable,
                           success)
from shared.notification_client import notify
from shared.security import (INCIDENT_CATEGORIES, SEVERITIES, clean_text, pagination,
                             parse_positive_int, reject_unknown_fields, require_fields,
                             require_json_object, utc_now, validate_choice, validate_date)
from shared.user_client import UserServiceUnavailable, get_user
from playbook_service.models import Playbook, ResponseAction
from playbook_service.repository import PlaybookRepository

bp = Blueprint("playbooks", __name__)
repo = PlaybookRepository()

# Fields / parameters each endpoint accepts (anything else -> 400)
CREATE_FIELDS = ["name", "description", "incident_category", "severity"]
ACTION_FIELDS = ["description", "step_number", "assigned_user_id"]
ACTION_UPDATE_FIELDS = ["status", "assigned_user_id", "completion_date"]
LIST_PARAMS = ["incident_category", "severity", "limit", "offset"]



def _check_assignee(user_id):
    """Inter-service call: the assigned user must exist and be Active.

    :param user_id: id from the body
    :type user_id: int
    :return: (user dict, None) when valid, or (None, error response) when not
    :rtype: tuple[dict or None, tuple[flask.Response, int] or None]
    """
    try:
        user = get_user(user_id)   # inter-service API call to the Users service
    except UserServiceUnavailable:
        return None, service_unavailable("Users service is unavailable, cannot verify the assigned user")
    if user is None:
        return None, not_found(f"User with id {user_id} not found")
    if user["account_status"] != "Active":
        return None, bad_request(f"User '{user['username']}' is {user['account_status'].lower()}")
    return user, None



# =====================================================================
# 1. Create Response Playbook - POST /playbooks
#    Student: Hayam Itani
# =====================================================================
@bp.route("/playbooks", methods=["POST"])
@require_permission("playbooks:create")
def create_playbook():
    """Create an incident response playbook. created_by = the logged-in admin.

    Body (JSON): name, description, incident_category, severity

    :return: 201 created | 400
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: empty body, missing/unknown field, invalid category or severity (400)
    """
    data = require_json_object(request.get_json(silent=True))
    reject_unknown_fields(data, CREATE_FIELDS)
    require_fields(data, CREATE_FIELDS)
    name = clean_text(data["name"], "name", 3, 150)
    description = clean_text(data["description"], "description", 3, 1000, multiline=True)
    incident_category = validate_choice(data["incident_category"], "incident_category", INCIDENT_CATEGORIES)
    severity = validate_choice(data["severity"], "severity", SEVERITIES)

    me = g.current_user
    playbook_id = repo.create(name, description, incident_category, severity, me["user_id"])
    log_event(user_id=me["user_id"], action="PLAYBOOK_CREATED",
              description=f"'{me['username']}' created playbook #{playbook_id} '{name}' "
                          f"({incident_category}, {severity})",
              severity="Information")
    return success("Playbook created successfully", repo.get_by_id(playbook_id).to_dict(), 201)



# =====================================================================
# 2. Retrieve All Playbooks - GET /playbooks
#    Student: Hayam Itani
# =====================================================================
@bp.route("/playbooks", methods=["GET"])
@require_permission("playbooks:list")
def list_playbooks():
    """All playbooks (optionally filtered by incident_category / severity), with action counts.

    :return: 200 with data, count, total
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: unknown parameter or invalid filter value (400)
    """
    unknown = sorted(set(request.args) - set(LIST_PARAMS))
    if unknown:
        raise ValidationError(f"Unknown query parameter(s): {', '.join(unknown)}",
                              {"allowed_parameters": LIST_PARAMS})
    filters = {}
    if request.args.get("incident_category"):
        filters["incident_category"] = validate_choice(request.args["incident_category"],
                                                       "incident_category", INCIDENT_CATEGORIES)
    if request.args.get("severity"):
        filters["severity"] = validate_choice(request.args["severity"], "severity", SEVERITIES)
    limit, offset = pagination(request.args)
    playbooks, total = repo.list(filters, limit, offset)
    message = "Playbooks retrieved successfully" if playbooks else "No playbooks match the criteria"
    return success(message, [p.to_dict(include_actions=False) for p in playbooks],
                   count=len(playbooks), total=total, filters=filters)



# =====================================================================
# 3. Retrieve Specific Playbook - GET /playbooks/{id}
#    Student: Hayam Itani
# =====================================================================
@bp.route("/playbooks/<playbook_id>", methods=["GET"])
@require_permission("playbooks:view")
def get_playbook(playbook_id):
    """Complete playbook including its response actions in step order.

    :param playbook_id: from the URL; positive integer (else 400)
    :type playbook_id: str
    :return: 200 | 400 bad id | 404
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: playbook_id is not a positive integer (400)
    """
    playbook_id = parse_positive_int(playbook_id, "id")
    playbook = repo.get_by_id(playbook_id)
    if playbook is None:
        return not_found(f"Playbook with id {playbook_id} not found")
    return success("Playbook retrieved successfully", playbook.to_dict())



# =====================================================================
# 4. Add Response Action - POST /playbooks/{id}/actions
#    Student: Hayam Itani
# =====================================================================
@bp.route("/playbooks/<playbook_id>/actions", methods=["POST"])
@require_permission("playbooks:add_action")
def add_response_action(playbook_id):
    """Add one ordered step to a playbook.

    Body (JSON): description, step_number, assigned_user_id (optional)

    :param playbook_id: from the URL; positive integer (else 400)
    :type playbook_id: str
    :return: 201 action + the playbook's ordered steps | 400 | 404 | 409 step number taken
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: invalid id, empty body, missing/unknown field, step number not > 0 (400)
    """
    playbook_id = parse_positive_int(playbook_id, "id")
    playbook = repo.get_by_id(playbook_id)
    if playbook is None:
        return not_found(f"Playbook with id {playbook_id} not found")

    data = require_json_object(request.get_json(silent=True))
    reject_unknown_fields(data, ACTION_FIELDS)
    require_fields(data, ["description", "step_number"])
    description = clean_text(data["description"], "description", 3, 500, multiline=True)
    step_number = parse_positive_int(data["step_number"], "step_number")

    assigned_user_id = None
    if data.get("assigned_user_id") is not None:
        assigned_user_id = parse_positive_int(data["assigned_user_id"], "assigned_user_id")
        _, error = _check_assignee(assigned_user_id)
        if error:
            return error

    try:
        action_id = repo.add_action(playbook_id, description, step_number, assigned_user_id)
    except sqlite3.IntegrityError:   # UNIQUE (playbook_id, step_number)
        return conflict(f"Step {step_number} already exists in playbook #{playbook_id}")

    me = g.current_user
    log_event(user_id=me["user_id"], action="RESPONSE_ACTION_ADDED",
              description=f"'{me['username']}' added step {step_number} (action #{action_id}) "
                          f"to playbook #{playbook_id}",
              severity="Information")
    if assigned_user_id:
        notify(assigned_user_id, "Response step assigned to you",
               f"Step {step_number} of playbook '{playbook.name}': {description}",
               "System Notification", playbook.severity)
    return success("Response action added successfully",
                   {"action": repo.get_action(action_id).to_dict(),
                    "playbook": repo.get_by_id(playbook_id).to_dict()}, 201)



# =====================================================================
# 5. Update Response Action Status - PUT /actions/{id}/status
#    Student: Hayam Itani
# =====================================================================
@bp.route("/actions/<action_id>/status", methods=["PUT"])
@require_permission("actions:update_status")
def update_action_status(action_id):
    """Update a step's status, assigned user and/or completion date.

    Body (JSON, at least one): status, assigned_user_id, completion_date (YYYY-MM-DD)

    Rules (D4 - write them in the report):
      * status only moves forward one step: Pending -> In Progress -> Completed
      * a step cannot move to In Progress / Completed while a lower step is not Completed
      * Completed is final (history is preserved; nothing changes after completion)
      * completed_at is set automatically when the status becomes Completed
        (or taken from completion_date - not in the future, not before the playbook was created)
      * completion_date without status Completed -> 400

    :param action_id: from the URL; positive integer (else 400)
    :type action_id: str
    :return: 200 with previous_status | 400 rule broken | 404
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: invalid id, empty body, unknown field, invalid status or date (400)
    """
    action_id = parse_positive_int(action_id, "id")
    action = repo.get_action(action_id)
    if action is None:
        return not_found(f"Response action with id {action_id} not found")
    data = require_json_object(request.get_json(silent=True))
    reject_unknown_fields(data, ACTION_UPDATE_FIELDS)
    if action.is_completed:
        return conflict(f"Action #{action_id} is completed; completed actions cannot change")

    new_status = action.status
    if "status" in data:
        new_status = validate_choice(data["status"], "status", ResponseAction.STATUSES)
        if new_status != action.status:
            if not action.can_move_to(new_status):
                return bad_request(f"Invalid status transition from {action.status} to {new_status}. "
                                   f"Next allowed status: {ResponseAction.NEXT_STATUS[action.status]}")
            waiting = repo.unfinished_steps_before(action.playbook_id, action.step_number)
            if waiting:
                return bad_request(f"Complete step(s) {', '.join(map(str, waiting))} of this playbook first")

    assigned_user_id = action.assigned_user_id
    assignee = None
    if "assigned_user_id" in data:
        assigned_user_id = parse_positive_int(data["assigned_user_id"], "assigned_user_id")
        assignee, error = _check_assignee(assigned_user_id)
        if error:
            return error

    completed_at = None
    if new_status == "Completed":
        if data.get("completion_date"):
            day = validate_date(data["completion_date"], "completion_date")
            if day > utc_now()[:10]:
                return bad_request("completion_date cannot be in the future")
            if day < repo.get_by_id(action.playbook_id).created_at[:10]:
                return bad_request("completion_date cannot be before the playbook was created")
            completed_at = f"{day} 00:00:00"
        else:
            completed_at = utc_now()
    elif data.get("completion_date"):
        return bad_request("completion_date can only be set when the status becomes Completed")

    if new_status == action.status and assigned_user_id == action.assigned_user_id:
        return success("No changes: the values sent are the same as the stored ones", action.to_dict())

    repo.update_action(action_id, new_status, assigned_user_id, completed_at)
    me = g.current_user
    log_event(user_id=me["user_id"], action="RESPONSE_ACTION_UPDATED",
              description=f"'{me['username']}' updated step {action.step_number} (action #{action_id}) "
                          f"of playbook #{action.playbook_id}: status {action.status} to {new_status}, "
                          f"assigned user {action.assigned_user_id} to {assigned_user_id}",
              severity="Information")
    if assignee and assigned_user_id != action.assigned_user_id:
        notify(assigned_user_id, "Response step assigned to you",
               f"Step {action.step_number} of playbook #{action.playbook_id}: {action.description}",
               "System Notification", "Medium")
    return success("Response action updated successfully", repo.get_action(action_id).to_dict(),
                   previous_status=action.status)



# =====================================================================
# 6. Delete Playbook - DELETE /playbooks/{id}
#    Student: Hayam Itani
# =====================================================================
@bp.route("/playbooks/<playbook_id>", methods=["DELETE"])
@require_permission("playbooks:delete")
def delete_playbook(playbook_id):
    """Delete a playbook and its response actions (ON DELETE CASCADE). Admin only.

    :param playbook_id: from the URL; positive integer (else 400)
    :type playbook_id: str
    :return: 200 | 404
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: playbook_id is not a positive integer (400)
    """
    playbook_id = parse_positive_int(playbook_id, "id")
    playbook = repo.get_by_id(playbook_id)
    if playbook is None:
        return not_found(f"Playbook with id {playbook_id} not found")
    repo.delete(playbook_id)
    me = g.current_user
    log_event(user_id=me["user_id"], action="PLAYBOOK_DELETED",
              description=f"Administrator '{me['username']}' deleted playbook #{playbook_id} "
                          f"'{playbook.name}' and its {len(playbook.actions)} response action(s)",
              severity="Warning")
    return success("Playbook deleted successfully",
                   {"playbook_id": playbook_id, "actions_deleted": len(playbook.actions)})

