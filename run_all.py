"""
Starts the services in one terminal:
    python run_all.py
  Users and Identity Management  -> port 5001
  Security Audit Logging         -> port 5005
  Notification and Alert Mgmt    -> port 5008
  Incident Management              -> port 5003
  Threat Intelligence            -> port 5004
  Playbook Management            -> port 5009
Press Ctrl+C to stop all of them.
(You can also run each one in its own terminal: python user_service/app.py, ...)
"""
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from shared.config import (AUDIT_SERVICE_URL, NOTIFICATION_SERVICE_URL,  # noqa: E402
                           USER_SERVICE_URL, INCIDENT_SERVICE_URL, THREAT_SERVICE_URL)
from shared.db import init_db                                             # noqa: E402

SERVICES = [
    ("Users", os.path.join(ROOT, "user_service", "app.py"), USER_SERVICE_URL),
    ("Audit Logging", os.path.join(ROOT, "audit_service", "app.py"), AUDIT_SERVICE_URL),
    ("Notifications", os.path.join(ROOT, "notification_service", "app.py"), NOTIFICATION_SERVICE_URL),
    ("Incidents", os.path.join(ROOT, "incident_service", "app.py"), INCIDENT_SERVICE_URL),
    ("Threats", os.path.join(ROOT, "threat_service", "app.py"), THREAT_SERVICE_URL),
]


def main():
    init_db()   # create the schema once before the services start
    processes = []
    for name, script, url in SERVICES:
        processes.append(subprocess.Popen([sys.executable, script], cwd=ROOT))
        print(f"Started {name:14} -> {url}")
    print("All services running. Press Ctrl+C to stop.")
    try:
        while True:
            for (name, _, _), proc in zip(SERVICES, processes):
                if proc.poll() is not None:
                    print(f"{name} service stopped with exit code {proc.returncode}")
                    raise KeyboardInterrupt
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping services...")
        for proc in processes:
            proc.terminate()
        for proc in processes:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    main()
