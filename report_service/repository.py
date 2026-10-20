from shared.db import get_db

# this service doesn't have its own table, it only reads and counts rows from the
# tables of the other services. table and column names are only ever written here,
# never taken from the request

# these lists are used to always show every value in the report, even if its count is 0
SEVERITIES = ["Low", "Medium", "High", "Critical"]
INCIDENT_STATUSES = ["Open", "Under Investigation",
                     "Mitigated", "Resolved", "Closed"]
VULN_STATUSES = ["Open", "Under Investigation",
                 "In Progress", "Resolved", "Closed"]
LOGIN_ATTEMPT_ACTIONS = ("LOGIN_SUCCESS", "LOGIN_FAILED", "LOGIN_BLOCKED")


class ReportRepository:
    # runs a query that returns one number (like a COUNT), and gives 0 instead of None
    def _scalar(self, sql, params=()):
        conn = get_db()
        try:
            return conn.execute(sql, params).fetchone()[0] or 0
        finally:
            conn.close()

    # counts rows per value of a column, e.g. {"Low": 2, "High": 1}.
    # if expected is given, the keys come out in that order and missing ones are set to 0
    def _grouped(self, table, column, expected=None):
        conn = get_db()
        try:
            rows = conn.execute(
                f"SELECT {column}, COUNT(*) FROM {table} GROUP BY {column}").fetchall()
        finally:
            conn.close()
        counts = {r[0]: r[1] for r in rows}
        if expected:
            ordered = {key: counts.pop(key, 0) for key in expected}
            # anything left that wasn't in expected still gets added at the end
            ordered.update(counts)
            return ordered
        return counts

    def summary(self):
        return {
            "users": self._scalar("SELECT COUNT(*) FROM users"),
            "assets": self._scalar("SELECT COUNT(*) FROM assets"),
            "open_incidents": self._scalar("SELECT COUNT(*) FROM incidents WHERE status = 'Open'"),
            "critical_threats": self._scalar("SELECT COUNT(*) FROM threats WHERE severity = 'Critical'"),
            "open_vulnerabilities": self._scalar(
                "SELECT COUNT(*) FROM vulnerabilities WHERE status = 'Open'"),
        }

    def incidents(self):
        return {
            "total_incidents": self._scalar("SELECT COUNT(*) FROM incidents"),
            "incidents_by_severity": self._grouped("incidents", "severity", SEVERITIES),
            "incidents_by_status": self._grouped("incidents", "status", INCIDENT_STATUSES),
        }

    def assets(self):
        return {
            "total_assets": self._scalar("SELECT COUNT(*) FROM assets"),
            "critical_assets": self._scalar(
                "SELECT COUNT(*) FROM assets WHERE criticality_level = 'Critical'"),
            "assets_by_type": self._grouped("assets", "asset_type"),
        }

    def threats(self):
        # newest 5 threats, threat_id is the tie breaker when two have the same date
        conn = get_db()
        try:
            recent = conn.execute(
                "SELECT threat_id, threat_type, threat_value, severity, date_added FROM threats "
                "ORDER BY date_added DESC, threat_id DESC LIMIT 5").fetchall()
        finally:
            conn.close()
        return {
            "total_threats": self._scalar("SELECT COUNT(*) FROM threats"),
            "threats_by_severity": self._grouped("threats", "severity", SEVERITIES),
            "threats_by_type": self._grouped("threats", "threat_type"),
            "recent_threats": [dict(r) for r in recent],
        }

    def vulnerabilities(self):
        # the critical ones are listed in full, highest cvss score first
        conn = get_db()
        try:
            critical = conn.execute(
                "SELECT vulnerability_id, title, cve_id, cvss_score, asset_id, status "
                "FROM vulnerabilities WHERE severity = 'Critical' "
                "ORDER BY cvss_score DESC, vulnerability_id").fetchall()
        finally:
            conn.close()
        return {
            "total_vulnerabilities": self._scalar("SELECT COUNT(*) FROM vulnerabilities"),
            "vulnerabilities_by_severity": self._grouped("vulnerabilities", "severity", SEVERITIES),
            "vulnerabilities_by_status": self._grouped("vulnerabilities", "status", VULN_STATUSES),
            "critical_vulnerabilities": {"count": len(critical), "items": [dict(r) for r in critical]},
        }

    def activity(self):
        # one ? per action name for the IN (...) part of the query
        marks = ",".join("?" * len(LOGIN_ATTEMPT_ACTIONS))
        conn = get_db()
        try:
            # the 5 actions that show up the most in the audit logs
            top = conn.execute(
                "SELECT action, COUNT(*) AS n FROM logs GROUP BY action "
                "ORDER BY n DESC, action LIMIT 5").fetchall()
        finally:
            conn.close()
        return {
            "total_user_activities": self._scalar("SELECT COUNT(*) FROM logs"),
            "login_attempts": self._scalar(
                f"SELECT COUNT(*) FROM logs WHERE action IN ({marks})", LOGIN_ATTEMPT_ACTIONS),
            "failed_login_attempts": self._scalar(
                "SELECT COUNT(*) FROM logs WHERE action = 'LOGIN_FAILED'"),
            "most_performed_actions": [{"action": r["action"], "count": r["n"]} for r in top],
        }
