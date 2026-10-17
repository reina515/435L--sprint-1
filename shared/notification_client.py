"""
Client used by ANY service to create notifications through the
Notification and Alert Management Service (POST /notifications).

Teammates can use it from their services, for example when an incident is assigned:

    from shared.notification_client import notify
    notify(analyst_id, "New incident assigned", "Incident #12 was assigned to you",
           "Incident Assignment", "High")
"""
import logging

from shared.config import NOTIFICATION_SERVICE_URL
from shared.service_client import ServiceClient

log = logging.getLogger("notification_client")
_client = ServiceClient(NOTIFICATION_SERVICE_URL)


def notify(user_id, title, message, notification_type="System Notification", severity="Low"):
    status, body = _client.post("/notifications", json={
        "user_id": user_id,
        "title": title[:150],
        "message": message[:2000],
        "notification_type": notification_type,
        "severity": severity,
    })
    if status != 201:
        log.error("Notification for user %s not created (HTTP %s): %s", user_id, status, body)
        return None
    return body.get("data", {}).get("notification_id")
