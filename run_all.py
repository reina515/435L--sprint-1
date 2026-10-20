import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from shared.config import (AUDIT_SERVICE_URL, NOTIFICATION_SERVICE_URL,
                           USER_SERVICE_URL, INCIDENT_SERVICE_URL, THREAT_SERVICE_URL, PLAYBOOK_SERVICE_URL)
from shared.db import init_db

SERVICES = [
    ("Users", os.path.join(ROOT, "user_service", "app.py"), USER_SERVICE_URL),
    ("Audit Logging", os.path.join(ROOT, "audit_service", "app.py"), AUDIT_SERVICE_URL),
    ("Notifications", os.path.join(ROOT, "notification_service", "app.py"), NOTIFICATION_SERVICE_URL),
    ("Incidents", os.path.join(ROOT, "incident_service", "app.py"), INCIDENT_SERVICE_URL),
    ("Threats", os.path.join(ROOT, "threat_service", "app.py"), THREAT_SERVICE_URL),
    ("Playbooks", os.path.join(ROOT, "playbook_service", "app.py"), PLAYBOOK_SERVICE_URL),
]


# runs my three services at the same time and stops them all with ctrl c
def main():
    init_db()
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
