import logging

from shared.config import NOTIFICATION_SERVICE_URL, ROUTE_PREFIX
from shared.service_client import ServiceClient

log = logging.getLogger("notification_client")
_client = ServiceClient(NOTIFICATION_SERVICE_URL)


# asks the notification service to create a notification and gives back its id, or None if it failed
def notify(user_id, title, message, notification_type="System Notification", severity="Low"):
    status, body = _client.post(f"{ROUTE_PREFIX}/notifications", json={
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
