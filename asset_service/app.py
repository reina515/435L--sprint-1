import os
import sys

# when we run "python asset_service/app.py" python only sees the asset_service folder,
# so we add the project root to the path first, otherwise "shared" can't be imported
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")))

from shared.app_factory import create_app, run
from shared.config import ASSET_SERVICE_PORT, HAMED_ROUTE_PREFIX
from asset_service.routes import bp

# runs on port 5002 and every route starts with /Hamed_Bou_Saleh
app = create_app("Asset Management Service", "asset_service", bp,
                 audit_name="Assets", url_prefix=HAMED_ROUTE_PREFIX)

if __name__ == "__main__":
    run(app, ASSET_SERVICE_PORT)
