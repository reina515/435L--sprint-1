import os
import sys

# same as the other services, add the project root so the imports below work
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")))

from shared.app_factory import create_app, run
from shared.config import HAMED_ROUTE_PREFIX, REPORT_SERVICE_PORT
from report_service.routes import bp

# runs on port 5006 and every route starts with /Hamed_Bou_Saleh
app = create_app("Security Reports Service", "report_service", bp,
                 audit_name="Reports", url_prefix=HAMED_ROUTE_PREFIX)

if __name__ == "__main__":
    run(app, REPORT_SERVICE_PORT)
