import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.app_factory import create_app, run
from shared.config import ROUTE_PREFIX, NOTIFICATION_SERVICE_PORT
from notification_service.routes import bp

app = create_app("Notification and Alert Management Service", "notification_service", bp,
                 audit_name="Notifications", url_prefix=ROUTE_PREFIX)

if __name__ == "__main__":
    run(app, NOTIFICATION_SERVICE_PORT)
