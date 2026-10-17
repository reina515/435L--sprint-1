"""
Client used by ANY service to write to the Security Audit Logging Service.

    from shared.audit_client import log_event
    log_event(user_id=5, action="ASSET_UPDATED", description="...", severity="Information")

It sends POST /logs to the audit service with the internal service key.
Inside the audit service itself, a "local writer" is registered so the log is
written directly to the database instead of the service calling itself.

If the audit service is unreachable the event is still written to the local
file logs/<service>.log, so no security event is silently lost.
"""
import logging

from shared.config import AUDIT_SERVICE_URL
from shared.service_client import ServiceClient

log = logging.getLogger("audit_client")
_client = ServiceClient(AUDIT_SERVICE_URL)
_state = {"service_name": "Unknown", "local_writer": None}


def configure(service_name, local_writer=None):
    _state["service_name"] = service_name
    _state["local_writer"] = local_writer


def log_event(user_id, action, description, severity="Information", related_service=None):
    payload = {
        "user_id": user_id,
        "action": action,
        "description": description[:1000],
        "severity": severity,
        "related_service": related_service or _state["service_name"],
    }
    # Always keep a local copy as well (Lab 2 item 9: logging and monitoring)
    log.info("AUDIT %s | user=%s | %s | %s", severity, user_id, action, description)

    if _state["local_writer"]:
        try:
            _state["local_writer"](**payload)
            return True
        except Exception as exc:  # never break the request because logging failed
            log.error("Local audit write failed: %s", exc)
            return False

    status, _ = _client.post("/logs", json=payload)
    if status != 201:
        log.error("Audit service did not store the event (HTTP %s): %s", status, payload)
        return False
    return True
