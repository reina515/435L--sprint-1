from flask import Blueprint, g, request

from shared.audit_client import log_event
from shared.auth import require_permission
from shared.errors import ValidationError, conflict, not_found, service_unavailable, success
from shared.security import (clean_text, pagination, parse_positive_int, reject_unknown_fields,
                             require_fields, require_json_object, validate_choice)
from shared.user_client import UserServiceUnavailable, get_user
from asset_service.repository import AssetRepository
from asset_service.validators import (
    ASSET_STATUSES, ASSET_TYPES, CRITICALITY_LEVELS, validate_ip)

bp = Blueprint("assets", __name__)
repo = AssetRepository()

# fields the client is allowed to send when creating, and the ones that can't be missing.
# operating_system, location and status are optional (status defaults to Active)
CREATE_FIELDS = ["asset_name", "asset_type", "ip_address", "operating_system", "owner_id",
                 "department", "location", "criticality_level", "status"]
REQUIRED_ON_CREATE = ["asset_name", "asset_type", "ip_address", "owner_id", "department",
                      "criticality_level"]


# POST /assets, only the admin can add assets
@bp.route("/assets", methods=["POST"])
@require_permission("assets:create")
def add_asset():
    data = require_json_object(request.get_json(silent=True))
    # anything extra in the body is rejected instead of being silently ignored
    reject_unknown_fields(data, CREATE_FIELDS)
    require_fields(data, REQUIRED_ON_CREATE)

    # validate and clean every field before it gets anywhere near the database
    asset_name = clean_text(data["asset_name"], "asset_name", 2, 100)
    asset_type = validate_choice(data["asset_type"], "asset_type", ASSET_TYPES)
    ip_address = validate_ip(data["ip_address"])
    department = clean_text(data["department"], "department", 2, 60)
    criticality = validate_choice(
        data["criticality_level"], "criticality_level", CRITICALITY_LEVELS)
    status = validate_choice(
        data.get("status", "Active"), "status", ASSET_STATUSES)
    owner_id = parse_positive_int(data["owner_id"], "owner_id")
    operating_system = (clean_text(data["operating_system"], "operating_system", 1, 60)
                        if data.get("operating_system") else None)
    location = clean_text(data["location"], "location",
                          1, 100) if data.get("location") else None

    # the owner is a user, and users live in the users service, so we call it
    # to make sure this owner_id actually exists
    try:
        owner = get_user(owner_id)
    except UserServiceUnavailable:
        return service_unavailable("Users service is unavailable, cannot verify the owner")
    if owner is None:
        return not_found(f"Owner user with id {owner_id} not found")

    asset_id = repo.create(asset_name, asset_type, ip_address, operating_system, owner_id,
                           department, location, criticality, status)
    # send a log to the audit service so we know who added what
    log_event(user_id=g.current_user["user_id"], action="ASSET_CREATED",
              description=f"Asset #{asset_id} '{asset_name}' ({asset_type}, {criticality}) "
              f"added by '{g.current_user['username']}'",
              severity="Information")
    return success("Asset created successfully", repo.get_by_id(asset_id).to_dict(), 201)


# PUT /assets/<id>, admin only. ip, type, os and location can't be changed after creation
UPDATE_FIELDS = ["asset_name", "owner_id",
                 "department", "criticality_level", "status"]


@bp.route("/assets/<asset_id>", methods=["PUT"])
@require_permission("assets:update")
def update_asset(asset_id):
    asset_id = parse_positive_int(asset_id, "asset_id")
    data = require_json_object(request.get_json(silent=True))
    reject_unknown_fields(data, UPDATE_FIELDS)

    asset = repo.get_by_id(asset_id)
    if asset is None:
        return not_found(f"Asset with id {asset_id} not found")

    # only the fields that were actually sent end up in changes
    changes = {}
    if "asset_name" in data:
        changes["asset_name"] = clean_text(
            data["asset_name"], "asset_name", 2, 100)
    if "department" in data:
        changes["department"] = clean_text(
            data["department"], "department", 2, 60)
    if "criticality_level" in data:
        changes["criticality_level"] = validate_choice(data["criticality_level"],
                                                       "criticality_level", CRITICALITY_LEVELS)
    if "status" in data:
        changes["status"] = validate_choice(
            data["status"], "status", ASSET_STATUSES)
    if "owner_id" in data:
        # same check as in create, the new owner has to exist in the users service
        owner_id = parse_positive_int(data["owner_id"], "owner_id")
        try:
            owner = get_user(owner_id)
        except UserServiceUnavailable:
            return service_unavailable("Users service is unavailable, cannot verify the owner")
        if owner is None:
            return not_found(f"Owner user with id {owner_id} not found")
        changes["owner_id"] = owner_id

    # build something like "status: Active to Inactive" for the audit log before saving
    summary = ", ".join(
        f"{k}: {getattr(asset, k)} to {v}" for k, v in changes.items())
    repo.update(asset_id, changes)
    log_event(user_id=g.current_user["user_id"], action="ASSET_UPDATED",
              description=f"Asset #{asset_id} updated by '{g.current_user['username']}' ({summary})",
              severity="Information")
    return success("Asset updated successfully", repo.get_by_id(asset_id).to_dict())


# DELETE /assets/<id>, admin only
@bp.route("/assets/<asset_id>", methods=["DELETE"])
@require_permission("assets:delete")
def delete_asset(asset_id):
    asset_id = parse_positive_int(asset_id, "asset_id")
    asset = repo.get_by_id(asset_id)
    if asset is None:
        return not_found(f"Asset with id {asset_id} not found")

    # if incidents or vulnerabilities still use this asset we return 409 instead of deleting,
    # otherwise those records would point to an asset that doesn't exist anymore
    incidents, vulnerabilities = repo.count_references(asset_id)
    if incidents or vulnerabilities:
        return conflict(f"Asset cannot be deleted: it is referenced by {incidents} incident(s) "
                        f"and {vulnerabilities} vulnerability record(s)")

    repo.delete(asset_id)
    # deleting is logged as a warning since it can't be undone
    log_event(user_id=g.current_user["user_id"], action="ASSET_DELETED",
              description=f"Asset #{asset_id} '{asset.asset_name}' deleted by "
              f"'{g.current_user['username']}'",
              severity="Warning")
    return success("Asset deleted successfully")


# GET /assets, admin and auditor can see the full list
@bp.route("/assets", methods=["GET"])
@require_permission("assets:list")
def list_assets():
    limit, offset = pagination(request.args)
    # search with no filters returns everything, so no need for a separate query
    assets, total = repo.search({}, limit, offset)
    return success("Assets retrieved successfully", [a.to_dict() for a in assets],
                   count=len(assets), total=total)


# GET /assets/search?name=&type=&ip=&department=&criticality=
# if more than one filter is given they are combined with AND
SEARCH_PARAMS = ["name", "type", "ip",
                 "department", "criticality", "limit", "offset"]


@bp.route("/assets/search", methods=["GET"])
@require_permission("assets:search")
def search_assets():
    args = request.args
    # a typo like ?nmae=x should give an error, not quietly return all the assets
    unknown = sorted(set(args) - set(SEARCH_PARAMS))
    if unknown:
        raise ValidationError(f"Unknown search parameter(s): {', '.join(unknown)}",
                              {"allowed_parameters": SEARCH_PARAMS})
    # map the short query names to the real column names
    filters = {}
    if args.get("name"):
        filters["asset_name"] = clean_text(args["name"], "name", 1, 100)
    if args.get("type"):
        filters["asset_type"] = validate_choice(
            args["type"], "type", ASSET_TYPES)
    if args.get("ip"):
        filters["ip_address"] = validate_ip(args["ip"], "ip")
    if args.get("department"):
        filters["department"] = clean_text(
            args["department"], "department", 1, 60)
    if args.get("criticality"):
        filters["criticality_level"] = validate_choice(args["criticality"], "criticality",
                                                       CRITICALITY_LEVELS)
    limit, offset = pagination(args)
    assets, total = repo.search(filters, limit, offset)
    # no matches is still a 200, just with an empty list and a different message
    message = "Assets retrieved successfully" if assets else "No assets match the search criteria"
    return success(message, [a.to_dict() for a in assets], count=len(assets), total=total,
                   filters=filters)


# GET /assets/<id>, the analyst can also view a single asset (but not the full list)
@bp.route("/assets/<asset_id>", methods=["GET"])
@require_permission("assets:view")
def get_asset(asset_id):
    asset_id = parse_positive_int(asset_id, "asset_id")
    asset = repo.get_by_id(asset_id)
    if asset is None:
        return not_found(f"Asset with id {asset_id} not found")
    return success("Asset retrieved successfully", asset.to_dict())
