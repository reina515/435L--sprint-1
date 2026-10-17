"""
Users and Identity Management Service  ->  http://127.0.0.1:5001
Run from the project root:   python user_service/app.py
"""
import os
import sys

# Make the project root importable so `from shared...` works
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.app_factory import create_app, run          # noqa: E402
from shared.config import USER_SERVICE_PORT              # noqa: E402
from user_service.routes import bp                       # noqa: E402

app = create_app("Users and Identity Management Service", "user_service", bp, audit_name="Users")

if __name__ == "__main__":
    run(app, USER_SERVICE_PORT)
