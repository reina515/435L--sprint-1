"""
Threat Intelligence Service  ->  http://127.0.0.1:5004
Run from the project root:   python threat_service/app.py
Implemented by: Hayam Itani

Boilerplate: same shape as Reina's notification_service/app.py.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.app_factory import create_app, run              # noqa: E402
from shared.config import THREAT_SERVICE_PORT                # noqa: E402  (add it in Phase 2 first)
from threat_service.routes import bp                         # noqa: E402

# audit_name must match SERVICES in shared/security.py exactly
app = create_app("Threat Intelligence Service", "threat_service", bp,
                 audit_name="Threat Intelligence")

if __name__ == "__main__":
    run(app, THREAT_SERVICE_PORT)
