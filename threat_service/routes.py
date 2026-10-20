"""
Service 4 - Threat Intelligence Service (port 5004)
Implemented by: Hayam Itani   (also sent in the X-Student-Name response header)

Endpoints (all under /hayam-itani, the student's name, e.g. POST /hayam-itani/threats)
  POST   /threats          add indicator        (Admin)
  GET    /threats          list                 (Admin, Analyst, Auditor)
  GET    /threats/search   search               (Admin, Analyst | D3: Auditor)
  GET    /threats/{id}     one                  (Admin, Analyst, Auditor)
  PUT    /threats/{id}     update               (Admin)  - description, severity, source only
  DELETE /threats/{id}     delete               (Admin)

Audit logs written: THREAT_CREATED, THREAT_UPDATED, THREAT_DELETED (Warning). Denied requests are
  logged as UNAUTHORIZED_ACCESS / UNAUTHENTICATED_ACCESS by shared/auth.py.
Notifications sent: "Threat Alert" to every active analyst when a High or Critical indicator is added.
Calls to other services: Users (GET /internal/users to find the analysts), Audit (POST /logs),
  Notifications (POST /notifications).

"""
import sqlite3

from flask import Blueprint, g, request

from shared.audit_client import log_event
from shared.auth import require_permission
from shared.errors import ValidationError, bad_request, conflict, not_found, success
from shared.notification_client import notify
from shared.permissions import ANALYST
from shared.security import (SEVERITIES, clean_text, pagination, parse_positive_int,
                             reject_unknown_fields, require_fields, require_json_object,
                             validate_choice)
from shared.user_client import UserServiceUnavailable, get_users_by_role
from threat_service.models import Threat
from threat_service.repository import ThreatRepository
from threat_service.validators import validate_threat_value

bp = Blueprint("threats", __name__, url_prefix="/hayam-itani")
repo = ThreatRepository()

# Fields / parameters each endpoint accepts (anything else -> 400)
CREATE_FIELDS = ["threat_type", "threat_value", "description", "severity", "source"]
UPDATE_FIELDS = ["description", "severity", "source"]
SEARCH_PARAMS = ["type", "value", "severity", "source", "limit", "offset"]


# =====================================================================
# 1. Add Threat Indicator - POST /threats
#    Student: Hayam Itani
# =====================================================================
@bp.route("/threats", methods=["POST"])
@require_permission("threats:create")
def create_threat():
    """Add a threat indicator.

    Body (JSON): threat_type, threat_value, description, severity, source

    :return: 201 created | 400 invalid format | 409 duplicate (same type + value)
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: empty body, missing/unknown field, invalid type, severity or value (400)
    """    
    data = require_json_object(request.get_json(silent=True))
    reject_unknown_fields(data, CREATE_FIELDS)
    require_fields(data, CREATE_FIELDS)
    threat_type = validate_choice(data["threat_type"], "threat_type", Threat.TYPES)
    severity = validate_choice(data["severity"], "severity", SEVERITIES)
    description = clean_text(data["description"], "description", 3, 1000, multiline=True)
    source = clean_text(data["source"], "source", 2, 100)
    threat_value = validate_threat_value(threat_type, data["threat_value"])

    existing = repo.find_by_type_and_value(threat_type, threat_value)
    if existing:
        return conflict(f"{threat_type} '{threat_value}' already exists (threat id {existing.threat_id})")
    try:
        threat_id = repo.create(threat_type, threat_value, description, severity, source)
    except sqlite3.IntegrityError:   # two identical requests at the same moment
        return conflict(f"{threat_type} '{threat_value}' already exists")

    me = g.current_user
    log_event(user_id=me["user_id"], action="THREAT_CREATED",
              description=f"'{me['username']}' added {severity} {threat_type} indicator "
                          f"#{threat_id}: {threat_value}",
              severity="Information")

    if severity in ("High", "Critical"):
        try:
            analysts = get_users_by_role(ANALYST)
        except UserServiceUnavailable:
            analysts = []   # the threat is saved anyway; the alert is best-effort
        for analyst in analysts:
            notify(analyst["user_id"], f"New {severity} threat indicator",
                   f"{threat_type} '{threat_value}' was added to threat intelligence (source: {source}).",
                   "Threat Alert", severity)

    return success("Threat indicator added successfully", repo.get_by_id(threat_id).to_dict(), 201)



# =====================================================================
# 2. Retrieve All Threat Indicators - GET /threats
#    Student: Hayam Itani
# =====================================================================
@bp.route("/threats", methods=["GET"])
@require_permission("threats:list")
def list_threats():
    """All threat indicators with severity, source and date added, newest first.

    :return: 200 with data, count, total
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: invalid limit or offset (400)
    """
    limit, offset = pagination(request.args)
    threats, total = repo.search({}, limit, offset)
    message = "Threat indicators retrieved successfully" if threats else "No threat indicators stored yet"
    return success(message, [t.to_dict() for t in threats], count=len(threats), total=total)



# =====================================================================
# 4. Search Threat Indicators - GET /threats/search?type=&value=&severity=&source=
#    Student: Hayam Itani
#    (kept above /threats/<id>, like Reina's search route)
# =====================================================================
@bp.route("/threats/search", methods=["GET"])
@require_permission("threats:search")
def search_threats():
    """Search by type, value (partial), severity, source (partial). Criteria are combined with AND.

    :return: 200 with data, count, total, filters | 400 unknown parameter / invalid value
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: unknown parameter or invalid value (400)
    """
    args = request.args
    unknown = sorted(set(args) - set(SEARCH_PARAMS))
    if unknown:
        raise ValidationError(f"Unknown search parameter(s): {','.join(unknown)}",{"allowed_parameters": SEARCH_PARAMS})
    filters = {}
    if args.get("type"):
        filters["threat_type"] = validate_choice(args["type"], "type", Threat.TYPES)
    if args.get("severity"):
        filters["severity"] = validate_choice(args["severity"], "severity", SEVERITIES)
    if args.get("value"):
        filters["threat_value"] = clean_text(args["value"], "value", 1, 255)
    if args.get("source"):
        filters["source"] = clean_text(args["source"], "source", 1, 100)
    if not filters:
        raise ValidationError("Give at least one search criterion: type, value, severity or source")
    
    limit, offset = pagination(args)
    threats, total = repo.search(filters, limit, offset)
    message = ("Threat indicators retrieved successfully" if threats
               else "No threat indicators match the search criteria")
    return success(message, [t.to_dict() for t in threats], count=len(threats), total=total,
                   filters=filters)


# =====================================================================
# 3. Retrieve Specific Threat Indicator - GET /threats/{id}
#    Student: Hayam Itani
# =====================================================================
@bp.route("/threats/<threat_id>", methods=["GET"])
@require_permission("threats:view")
def get_threat(threat_id):
    """One threat indicator.

    :param threat_id: from the URL; positive integer (else 400)
    :type threat_id: str
    :return: 200 | 404
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: threat_id is not a positive integer (400)
    """
    threat_id = parse_positive_int(threat_id, "id")
    threat = repo.get_by_id(threat_id)
    if threat is None:
        return not_found(f"Threat indicator with id {threat_id} not found")
    return success("Threat indicator retrieved successfully", threat.to_dict())



# =====================================================================
# 5. Update Threat Information - PUT /threats/{id}
#    Student: Hayam Itani
# =====================================================================
@bp.route("/threats/<threat_id>", methods=["PUT"])
@require_permission("threats:update")
def update_threat(threat_id):
    """Update description, severity and/or source.

    Type and value are NOT updatable: they identify the indicator (uniqueness rule).
    To change them, delete and add again.

    :param threat_id: from the URL; positive integer (else 400)
    :type threat_id: str
    :return: 200 with the previous and new values | 400 | 404
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: invalid id, empty body, unknown or non-updatable field, invalid value (400)
    """
    threat_id = parse_positive_int(threat_id, "id")
    threat = repo.get_by_id(threat_id)
    if threat is None:
        return not_found(f"Threat indicator with id {threat_id} not found")

    data = require_json_object(request.get_json(silent=True))
    if "threat_type" in data or "threat_value" in data:
        return bad_request("threat_type and threat_value cannot be changed: they identify the indicator. "
                           "Delete it and add a new one instead")
    reject_unknown_fields(data, UPDATE_FIELDS)

    changes = {}
    if "description" in data:
        changes["description"] = clean_text(data["description"], "description", 3, 1000, multiline=True)
    if "severity" in data:
        changes["severity"] = validate_choice(data["severity"], "severity", SEVERITIES)
    if "source" in data:
        changes["source"] = clean_text(data["source"], "source", 2, 100)

    previous = {field: getattr(threat, field) for field in changes}
    changed = {field: value for field, value in changes.items() if previous[field] != value}
    if not changed:
        return success("No changes: the values sent are the same as the stored ones", threat.to_dict())

    repo.update(threat_id, changed)
    me = g.current_user
    log_event(user_id=me["user_id"], action="THREAT_UPDATED",
              description=f"'{me['username']}' updated threat #{threat_id}: "
                            + ", ".join(f"{f} '{previous[f]}' to '{v}'" for f, v in changed.items()),

              severity="Information")
    return success("Threat indicator updated successfully", repo.get_by_id(threat_id).to_dict(),
                   previous={f: previous[f] for f in changed})

    




# =====================================================================
# 6. Delete Threat Indicator - DELETE /threats/{id}
#    Student: Hayam Itani
# =====================================================================
@bp.route("/threats/<threat_id>", methods=["DELETE"])
@require_permission("threats:delete")
def delete_threat(threat_id):
    """Delete a threat indicator (Admin only; an Analyst gets 403 and the attempt is logged
    by require_permission automatically).

    :param threat_id: from the URL; positive integer (else 400)
    :type threat_id: str
    :return: 200 | 404
    :rtype: tuple[flask.Response, int]
    :raises ValidationError: threat_id is not a positive integer (400)
    """
    threat_id = parse_positive_int(threat_id, "id")
    threat = repo.get_by_id(threat_id)
    if threat is None:
        return not_found(f"Threat indicator with id {threat_id} not found")
    repo.delete(threat_id)
    me = g.current_user
    log_event(user_id=me["user_id"], action="THREAT_DELETED",
                description=f"Administrator '{me['username']}' deleted {threat.threat_type} indicator "
                            f"#{threat_id}: {threat.threat_value}",
                severity="Warning")
    return success("Threat indicator deleted successfully",
                    {"threat_id": threat_id, "threat_type": threat.threat_type,
                    "threat_value": threat.threat_value})
