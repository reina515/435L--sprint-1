import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.app_factory import create_app, run
from shared.config import ROUTE_PREFIX, AUDIT_SERVICE_PORT
from audit_service.routes import bp, local_writer

app = create_app("Security Audit Logging Service", "audit_service", bp,
                 audit_name="Audit Logging", local_audit_writer=local_writer, url_prefix=ROUTE_PREFIX)

if __name__ == "__main__":
    run(app, AUDIT_SERVICE_PORT)
