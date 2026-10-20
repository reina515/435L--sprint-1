import logging

from shared.config import AUDIT_SERVICE_URL, ROUTE_PREFIX
from shared.service_client import ServiceClient

log = logging.getLogger("audit_client")
_client = ServiceClient(AUDIT_SERVICE_URL)
_state = {"service_name": "Unknown", "local_writer": None}


# remembers which service is logging and if it can write logs directly without an http call
def configure(service_name, local_writer=None):
    _state["service_name"] = service_name
    _state["local_writer"] = local_writer


# sends an event to the audit service (or writes it locally) and returns True if it was saved
def log_event(user_id, action, description, severity="Information", related_service=None):
    payload = {
        "user_id": user_id,
        "action": action,
        "description": description[:1000],
        "severity": severity,
        "related_service": related_service or _state["service_name"],
    }
    log.info("AUDIT %s | user=%s | %s | %s", severity, user_id, action, description)

    if _state["local_writer"]:
        try:
            _state["local_writer"](**payload)
            return True
        except Exception as exc:
            log.error("Local audit write failed: %s", exc)
            return False

    status, _ = _client.post(f"{ROUTE_PREFIX}/logs", json=payload)
    if status != 201:
        log.error("Audit service did not store the event (HTTP %s): %s", status, payload)
        return False
    return True
