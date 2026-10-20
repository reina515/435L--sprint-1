"""
Service 3 - Incident Management Service (port 5003)
Implemented by: Hayam Itani   (also sent in the X-Student-Name response header)

Endpoints (all under /hayam-itani, the student's name, e.g. POST /hayam-itani/incidents)
  POST   /incidents               report an incident       (Admin, Employee)
  GET    /incidents               list                     (Admin, Auditor | D1: Analyst + Employee OWN)
  GET    /incidents/{id}          one, with notes          (Admin, Auditor: any | Analyst: assigned | Employee: reported)
  PUT    /incidents/{id}/assign   assign to an analyst     (Admin)
  PUT    /incidents/{id}/status   next lifecycle step      (Admin | Analyst: assigned)   D2: only Admin closes
  POST   /incidents/{id}/notes    add investigation note   (Admin | Analyst: assigned)

Audit logs written: INCIDENT_CREATED, INCIDENT_ASSIGNED, INCIDENT_STATUS_CHANGED,
  INVALID_STATUS_TRANSITION (Warning), INCIDENT_NOTE_ADDED. Denied requests are logged as
  UNAUTHORIZED_ACCESS / UNAUTHENTICATED_ACCESS by shared/auth.py.
Notifications sent: "Incident Assignment" to the assigned analyst; "Security Alert" to every
  administrator when a Critical incident is reported.
Calls to other services: Users (GET /internal/users/{id} to check the analyst), Audit (POST /logs),
  Notifications (POST /notifications). Assets: checked directly in the shared database until the
  Asset service exposes an internal endpoint.

"""

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

bp = Blueprint("incidents", __name__, url_prefix="/hayam-itani")
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

    :return: 201 and the created incident | 403 role not allowed | 404 asset not found
    :rtype: tuple[flask.Response, int]
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

    Query: status, severity (optional filters), limit, offset.
    Analysts only see incidents assigned to them and employees only the ones they reported (D1).

    :return: 200 with data (list), count and total
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: unknown query parameter or invalid filter value (400)
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
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: incident_id is not a positive integer (400)
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

    :param incident_id: from the URL; must be a positive integer (else 400)
    :type incident_id: str
    :return: 200 updated incident | 400 not an analyst | 404 incident/user missing |
        409 incident closed | 503 Users service down
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: invalid id, empty body, missing/unknown field (400)
    """
    incident_id = parse_positive_int(incident_id, "id")
    data = require_json_object(request.get_json(silent=True))
    reject_unknown_fields(data, ASSIGN_FIELDS)
    require_fields(data, ASSIGN_FIELDS)
    analyst_id = parse_positive_int(data["analyst_id"], "analyst_id")

    incident = repo.get_by_id(incident_id)
    if incident is None:
        return not_found(f"Incident with id {incident_id} not found")
    if incident.status == "Closed":
        return conflict(f"Incident #{incident_id} is closed and cannot be reassigned")

    try:
        analyst = get_user(analyst_id)   # inter-service API call to the Users service
    except UserServiceUnavailable:
        return service_unavailable("Users service is unavailable, cannot verify the analyst")
    if analyst is None:
        return not_found(f"User with id {analyst_id} not found")
    if analyst["role"] != ANALYST:
        return bad_request(f"User '{analyst['username']}' is not a Security Analyst "
                           f"(role: {analyst['role']})")
    if analyst["account_status"] != "Active":
        return bad_request(f"Analyst '{analyst['username']}' is {analyst['account_status'].lower()}")

    repo.assign(incident_id, analyst_id)
    me = g.current_user
    log_event(user_id=me["user_id"], action="INCIDENT_ASSIGNED",
              description=f"Administrator '{me['username']}' assigned incident #{incident_id} "
                          f"to analyst '{analyst['username']}'",
              severity="Information")
    notify(analyst_id, f"Incident #{incident_id} assigned to you",
           f"'{incident.title}' ({incident.severity}) was assigned to you by {me['username']}.",
           "Incident Assignment", incident.severity)
    return success("Incident assigned successfully", repo.get_by_id(incident_id).to_dict())



# =====================================================================
# 5. Update Incident Status - PUT /incidents/{id}/status
#    Student: Hayam Itani
# =====================================================================
@bp.route("/incidents/<incident_id>/status", methods=["PUT"])
@require_permission("incidents:status")
def update_incident_status(incident_id):
    """Move an incident one step: Open -> Under Investigation -> Mitigated -> Resolved -> Closed.

    Body (JSON): status. Only the assigned analyst (or an admin) may change it, one step at a time;
    only an admin may close (D2); "Under Investigation" needs an assigned analyst.

    :param incident_id: from the URL; must be a positive integer (else 400)
    :type incident_id: str
    :return: 200 with previous_status and new_status | 400 invalid transition | 403 | 404 |
        409 changed by another request
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: invalid id, empty body, unknown status value (400)
    """
    incident_id = parse_positive_int(incident_id, "id")
    data = require_json_object(request.get_json(silent=True))
    reject_unknown_fields(data, STATUS_FIELDS)
    require_fields(data, STATUS_FIELDS)
    new_status = validate_choice(data["status"], "status", Incident.STATUSES)

    incident = repo.get_by_id(incident_id)
    if incident is None:
        return not_found(f"Incident with id {incident_id} not found")
    if not owns_or_all(_owner_id(incident)):
        return deny("incidents:status", reason=f"tried to change the status of incident #{incident_id}, "
                                                f"which is not assigned to them")

    me = g.current_user
    old_status = incident.status
    if not incident.can_move_to(new_status):
        log_event(user_id=me["user_id"], action="INVALID_STATUS_TRANSITION",
                  description=f"'{me['username']}' tried to move incident #{incident_id} "
                              f"from {old_status} to {new_status}",
                  severity="Warning")
        return bad_request(f"Invalid status transition from {old_status} to {new_status}. "
                           f"Next allowed status: {incident.next_status() or 'none (incident is closed)'}")
    if new_status == "Closed" and me["role"] != ADMIN:   # D2: only administrators close incidents
        return deny("incidents:status", reason=f"tried to close incident #{incident_id}; "
                                                f"only administrators may close incidents")
    if new_status == "Under Investigation" and incident.assigned_analyst_id is None:
        return bad_request("Assign the incident to a Security Analyst before starting the investigation")

    if not repo.update_status(incident_id, old_status, new_status):
        return conflict("The incident status was changed by another request, reload and try again")
    log_event(user_id=me["user_id"], action="INCIDENT_STATUS_CHANGED",
              description=f"'{me['username']}' moved incident #{incident_id} "
                          f"from {old_status} to {new_status}",
              severity="Information")
    return success(f"Incident status updated from {old_status} to {new_status}",
                   repo.get_by_id(incident_id).to_dict(),
                   previous_status=old_status, new_status=new_status)



# =====================================================================
# 6. Add Investigation Notes - POST /incidents/{id}/notes
#    Student: Hayam Itani
# =====================================================================
@bp.route("/incidents/<incident_id>/notes", methods=["POST"])
@require_permission("incidents:add_note")
def add_investigation_note(incident_id):
    """Add an investigation note (analysis performed, evidence collected, actions taken).

    Body (JSON): content

    :param incident_id: from the URL; must be a positive integer (else 400)
    :type incident_id: str
    :return: 201 note + the incident with all its notes | 403 not assigned | 404 | 409 incident closed
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: invalid id, empty body, empty content (400)
    """
    incident_id = parse_positive_int(incident_id, "id")
    data = require_json_object(request.get_json(silent=True))
    reject_unknown_fields(data, NOTE_FIELDS)
    require_fields(data, NOTE_FIELDS)
    content = clean_text(data["content"], "content", 1, 2000, multiline=True)

    incident = repo.get_by_id(incident_id)
    if incident is None:
        return not_found(f"Incident with id {incident_id} not found")
    if not owns_or_all(_owner_id(incident)):
        return deny("incidents:add_note", reason=f"tried to add a note to incident #{incident_id}, "
                                                  f"which is not assigned to them")
    if incident.status == "Closed":
        return conflict(f"Incident #{incident_id} is closed; notes can no longer be added")

    me = g.current_user
    note_id = repo.add_note(incident_id, me["user_id"], content)
    log_event(user_id=me["user_id"], action="INCIDENT_NOTE_ADDED",
              description=f"'{me['username']}' added note #{note_id} to incident #{incident_id}",
              severity="Information")
    updated = repo.get_by_id(incident_id)
    note = next(n for n in updated.notes if n.note_id == note_id)
    return success("Investigation note added successfully",
                   {"note": note.to_dict(), "incident": updated.to_dict()}, 201)

