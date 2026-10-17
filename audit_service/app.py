"""
Security Audit Logging Service  ->  http://127.0.0.1:5005
Run from the project root:   python audit_service/app.py
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.app_factory import create_app, run              # noqa: E402
from shared.config import AUDIT_SERVICE_PORT                 # noqa: E402
from audit_service.routes import bp, local_writer            # noqa: E402

app = create_app("Security Audit Logging Service", "audit_service", bp,
                 audit_name="Audit Logging", local_audit_writer=local_writer)

if __name__ == "__main__":
    run(app, AUDIT_SERVICE_PORT)
