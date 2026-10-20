from flask import Blueprint

from shared.auth import require_permission
from shared.errors import success
from shared.security import utc_now
from report_service.repository import ReportRepository

# every report is read only and only the admin and the auditor are allowed to see them
bp = Blueprint("reports", __name__)
repo = ReportRepository()


# all the reports return the same shape, plus the time the report was generated
def report(message, data):
    return success(message, data, generated_at=utc_now())


# GET /reports/summary, a few overall numbers (users, assets, open incidents...)
@bp.route("/reports/summary", methods=["GET"])
@require_permission("reports:summary")
def summary_report():
    return report("Security summary report generated successfully", repo.summary())


# GET /reports/incidents, incidents grouped by severity and status
@bp.route("/reports/incidents", methods=["GET"])
@require_permission("reports:incidents")
def incident_report():
    return report("Incident report generated successfully", repo.incidents())


# GET /reports/assets
@bp.route("/reports/assets", methods=["GET"])
@require_permission("reports:assets")
def asset_report():
    return report("Asset report generated successfully", repo.assets())


# GET /reports/threats, includes the 5 most recent threats
@bp.route("/reports/threats", methods=["GET"])
@require_permission("reports:threats")
def threat_report():
    return report("Threat report generated successfully", repo.threats())


# GET /reports/vulnerabilities, also lists the critical ones
@bp.route("/reports/vulnerabilities", methods=["GET"])
@require_permission("reports:vulnerabilities")
def vulnerability_report():
    return report("Vulnerability report generated successfully", repo.vulnerabilities())


# GET /reports/activity, built from the audit logs (logins, failed logins, top actions)
@bp.route("/reports/activity", methods=["GET"])
@require_permission("reports:activity")
def activity_report():
    return report("User activity report generated successfully", repo.activity())
