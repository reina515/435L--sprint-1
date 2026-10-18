"""
Service 3 - Incident Management Service (port 5003)
Implemented by: Hayam Itani   (also sent in the X-Student-Name response header)

Endpoints
  POST   /incidents               report an incident       (Admin, Employee)
  GET    /incidents               list                     (Admin, Auditor | D1: Analyst + Employee OWN)
  GET    /incidents/{id}          one, with notes          (Admin, Auditor: any | Analyst: assigned | Employee: reported)
  PUT    /incidents/{id}/assign   assign to an analyst     (Admin)
  PUT    /incidents/{id}/status   next lifecycle step      (Admin | Analyst: assigned)   D2: only Admin closes
  POST   /incidents/{id}/notes    add investigation note   (Admin | Analyst: assigned)

TODO (fill in when done):
  Audit logs written: ...
  Notifications sent: ...
  Calls to other services: Users (GET /internal/users/{id}), Audit (POST /logs),
  Notifications (POST /notifications), Assets (GET /internal/assets/{id}, once B adds it).
"""
from warnings import filters

from flask import Blueprint, g, request

from shared.audit_client import log_event
from shared.auth import deny, owns_or_all, require_permission
from shared.errors import (ValidationError, bad_request, conflict, not_found, service_unavailable,
                           success)
from shared.notification_client import notify
from shared.permissions import ADMIN, ANALYST, EMPLOYEE, OWN
from shared.security import (INCIDENT_CATEGORIES, SEVERITIES, clean_text, pagination,
                             parse_positive_int, reject_unknown_fields, require_fields,
                             require_json_object, validate_choice)
from shared.user_client import UserServiceUnavailable, get_user, get_users_by_role
from incident_service.models import Incident
from incident_service.repository import IncidentRepository

bp = Blueprint("incidents", __name__)
repo = IncidentRepository()

CREATE_FIELDS = ["title", "description", "category", "severity", "asset_id"]   # brief: title, description, category, severity, affected asset (reporter = the caller)
ASSIGN_FIELDS = ["analyst_id"]   # brief: analyst id (the incident id is in the URL)
STATUS_FIELDS = ["status"]   # brief: new status
NOTE_FIELDS = ["content"]   # brief: note content
LIST_PARAMS = ["status", "severity", "limit", "offset"]     # e.g. status, severity, limit, offset


def _owner_id(incident):
    """Who "owns" an incident for OWN-scope checks.

    :param incident: the incident being accessed
    :type incident: Incident
    :return: assigned_analyst_id if the caller is an Analyst, reporter_id if an Employee
    :rtype: int or None
    """
    role = g.current_user["role"]
    if role == ANALYST:
        return incident.assigned_analyst_id
    elif role == EMPLOYEE:
        return incident.reporter_id
    return None   # Admin and Auditor have ALL scope, so this is never called for them


# =====================================================================
# 1. Create Incident - POST /incidents
#    Student: Hayam Itani
#    (also sent in the X-Student-Name response header)
# =====================================================================
@bp.route("/incidents", methods=["POST"])
@require_permission("incidents:create")
def create_incident():
    """Report a cybersecurity incident. The reporter is the logged-in user.

    Body (JSON): title, description, category, severity, asset_id

    :return: 201 and the created incident
    :raises ValidationError: empty body, missing/unknown field, invalid value (400)
    """
    data = require_json_object(request.get_json(silent=True))
    reject_unknown_fields(data, CREATE_FIELDS)
    require_fields(data, CREATE_FIELDS)
    title = clean_text(data["title"], "title", 3, 150)
    description = clean_text(data["description"], "description", 5, 2000, multiline=True)
    category = validate_choice(data["category"], "category", INCIDENT_CATEGORIES)
    severity = validate_choice(data["severity"], "severity", SEVERITIES)
    asset_id = parse_positive_int(data["asset_id"], "asset_id")

    if not repo.asset_exists(asset_id):
        return not_found(f"Asset with id {asset_id} not found")


    me = g.current_user
    incident_id = repo.create(title, description, category, severity, me["user_id"], asset_id)
    log_event(user_id=me["user_id"], action="INCIDENT_CREATED",
              description=f"Incident {incident_id} reported by {me['username']} with severity "
                          f"{severity} on asset {asset_id}",
              severity="Information")

    if severity == "Critical":
        try:
            admins = get_users_by_role(ADMIN)
        except UserServiceUnavailable:
            admins = [] #incident saved anyway if userService is unavailable
        for admin in admins:
            notify(admin["user_id"], f"Critical incident reported by {me['username']}",
                   f"Incident {incident_id} reported with severity Critical on asset {asset_id}",
                   "Security Alert", severity)
    return success("Incident created successfully", repo.get_by_id(incident_id).to_dict(), 201)


# =====================================================================
# 2. Retrieve All Incidents - GET /incidents
#    Student: Hayam Itani
# =====================================================================
@bp.route("/incidents", methods=["GET"])
@require_permission("incidents:list")
def list_incidents():
    """All incidents with their status and assigned analyst, newest first.

    Query: status, severity (optional filters), limit, offset

    :return: 200 with data (list), count and total
    """
    unknown = sorted(set(request.args) - set(LIST_PARAMS))
    if unknown:
        raise ValidationError(f"Unknown query parameter(s): {', '.join(unknown)}",
                              {"allowed_parameters": LIST_PARAMS})
    filters = {}
    if request.args.get("status"):
        filters["status"] = validate_choice(request.args["status"], "status", Incident.STATUSES)
    if request.args.get("severity"):
        filters["severity"] = validate_choice(request.args["severity"], "severity", SEVERITIES)

    if g.scope == OWN:   # D1: analysts see what is assigned to them, employees what they reported
        me = g.current_user
        if me["role"] == ANALYST:
            filters["assigned_analyst_id"] = me["user_id"]
        else:
            filters["reporter_id"] = me["user_id"]

    limit, offset = pagination(request.args)
    incidents, total = repo.list(filters, limit, offset)
    message = "Incidents retrieved successfully" if incidents else "No incidents match the criteria"
    return success(message, [i.to_dict(include_notes=False) for i in incidents],
                   count=len(incidents), total=total, filters=filters)


# =====================================================================
# 3. Retrieve Specific Incident - GET /incidents/{id}
#    Student: Hayam Itani
# =====================================================================
@bp.route("/incidents/<incident_id>", methods=["GET"])
@require_permission("incidents:view")
def get_incident(incident_id):
    """Full incident including its investigation notes.

    :param incident_id: from the URL; must be a positive integer (else 400)
    :type incident_id: str
    :return: 200 incident | 403 not yours (OWN scope) | 404 not found
    """
    incident_id = parse_positive_int(incident_id, "id")
    incident = repo.get_by_id(incident_id)
    if incident is None:
        return not_found(f"Incident with id {incident_id} not found")
    if not owns_or_all(_owner_id(incident)):
        return deny("incidents:view", reason=f"tried to view incident #{incident_id}, which is not theirs")
    return success("Incident retrieved successfully", incident.to_dict())
    


# =====================================================================
# 4. Assign Incident to Analyst - PUT /incidents/{id}/assign
#    Student: Hayam Itani
# =====================================================================
@bp.route("/incidents/<incident_id>/assign", methods=["PUT"])
@require_permission("incidents:assign")
def assign_incident(incident_id):
    """Assign an incident to a Security Analyst.

    Brief rules: the incident exists; the user has the Security Analyst role;
    the assignment is recorded in the audit log. (Plus: notify the analyst.)

    Body (JSON): analyst_id

    :return: 200 updated incident | 400 not an analyst | 404 incident/user missing | 503 Users down
    """
    # TODO 1  parse id; body checks (ASSIGN_FIELDS); parse_positive_int(analyst_id)
    # TODO 2  incident must exist -> 404. Decide what happens if it is Closed (e.g. 409 conflict)
    # TODO 3  Inter-service call: get_user(analyst_id) inside try/except UserServiceUnavailable
    #         -> 503 when the Users service is down, 404 when None
    # TODO 4  role must be "Security Analyst" and account_status "Active" -> bad_request(...) otherwise
    # TODO 5  repo.assign(...)
    # TODO 6  log_event(action="INCIDENT_ASSIGNED", ...)   <- the brief requires this one
    # TODO 7  notify(analyst_id, <title>, <message>, "Incident Assignment", incident.severity)
    # TODO 8  success("Incident assigned successfully", <updated incident dict>)
    raise NotImplementedError


# =====================================================================
# 5. Update Incident Status - PUT /incidents/{id}/status
#    Student: Hayam Itani
# =====================================================================
@bp.route("/incidents/<incident_id>/status", methods=["PUT"])
@require_permission("incidents:status")
def update_incident_status(incident_id):
    """Move an incident one step: Open -> Under Investigation -> Mitigated -> Resolved -> Closed.

    Body (JSON): status

    :return: 200 with previous_status and new status | 400 invalid transition | 403 | 404
    """
    # TODO 1  parse id; body checks (STATUS_FIELDS); validate_choice(status, "status", Incident.STATUSES)
    # TODO 2  incident must exist -> 404; OWN scope (an analyst must be the assigned one) -> deny
    # TODO 3  if not incident.can_move_to(new): log_event(... severity="Warning") and
    #         bad_request("Invalid status transition from X to Y. Next allowed status: Z")
    # TODO 4  D2: Resolved -> Closed only by an Admin -> deny(...) for anyone else
    # TODO 5  Optional: "Under Investigation" requires an assigned analyst
    # TODO 6  repo.update_status(id, old, new) -> False means changed meanwhile -> conflict(...)
    # TODO 7  log_event(action="INCIDENT_STATUS_CHANGED", ...)
    # TODO 8  success(<message>, <incident dict>, previous_status=..., new_status=...)
    raise NotImplementedError


# =====================================================================
# 6. Add Investigation Notes - POST /incidents/{id}/notes
#    Student: Hayam Itani
# =====================================================================
@bp.route("/incidents/<incident_id>/notes", methods=["POST"])
@require_permission("incidents:add_note")
def add_investigation_note(incident_id):
    """Add an investigation note (analysis performed, evidence collected, actions taken).

    Body (JSON): content

    :return: 201 note + the incident's notes | 403 | 404
    """
    # TODO 1  parse id; body checks (NOTE_FIELDS); clean_text(content, ..., multiline=True)
    # TODO 2  incident must exist -> 404; OWN scope (analyst must be assigned) -> deny
    # TODO 3  Decide: notes on a Closed incident? (e.g. 409)
    # TODO 4  repo.add_note(id, <caller id>, content)
    # TODO 5  log_event(action="INCIDENT_NOTE_ADDED", ...)
    # TODO 6  success("Investigation note added successfully", {...}, 201) - include the note and
    #         the updated incident so the screenshot shows the link between them
    raise NotImplementedError
