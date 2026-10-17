"""
Notification and Alert Management Service  ->  http://127.0.0.1:5008
Run from the project root:   python notification_service/app.py
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.app_factory import create_app, run              # noqa: E402
from shared.config import NOTIFICATION_SERVICE_PORT          # noqa: E402
from notification_service.routes import bp                   # noqa: E402

app = create_app("Notification and Alert Management Service", "notification_service", bp,
                 audit_name="Notifications")

if __name__ == "__main__":
    run(app, NOTIFICATION_SERVICE_PORT)
