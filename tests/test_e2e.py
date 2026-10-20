import os
import sqlite3
import sys
import time
import uuid

import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from shared.config import (AUDIT_SERVICE_URL as AUDIT, DATABASE_PATH,
                           NOTIFICATION_SERVICE_URL as NOTIF, SERVICE_API_KEY,
                           USER_SERVICE_URL as USERS, USE_HTTPS, SSL_CERT_FILE,
                           ROUTE_PREFIX)

USERS, AUDIT, NOTIF = USERS + ROUTE_PREFIX, AUDIT + ROUTE_PREFIX, NOTIF + ROUTE_PREFIX

if USE_HTTPS:
    os.environ["REQUESTS_CA_BUNDLE"] = SSL_CERT_FILE

RUN = uuid.uuid4().hex[:6]
STATE = {}
PASSWORDS = {"admin": "Admin@12345", "analyst": "Analyst@12345", "employee": "Employee@12345",
             "employee2": "Second#Pass2026", "auditor": "Auditor@12345"}


# logs in a test user and returns the auth header with the user info
def login(username, password=None):
    r = requests.post(f"{USERS}/users/login", json={"username": username,
                                                    "password": password or PASSWORDS[username]})
    assert r.status_code == 200, r.text
    data = r.json()["data"]
    return {"Authorization": f"Bearer {data['token']}"}, data["user"]


# shortcut to get the saved auth header of a test user
def H(name):
    return STATE["tokens"][name]


# shortcut to get the id of a test user
def uid(name):
    return STATE["users"][name]["user_id"]


# makes sure employee2 and the suspended user exist before the tests
def _ensure_extra_test_users():
    admin, _ = login("admin")
    extra = [("Second Employee", "employee2", "Second#Pass2026", "Active"),
             ("Suspended User", "suspended", "Paused#Pass2026", "Suspended")]
    for full_name, username, password, status in extra:
        if requests.get(f"{USERS}/users/{username}", headers=admin).status_code == 404:
            r = requests.post(f"{USERS}/users/register", headers=admin, json={
                "full_name": full_name, "username": username, "email": f"{username}@security.local",
                "password": password, "department": "Finance", "role": "Regular Employee",
                "account_status": status})
            assert r.status_code == 201, r.text


# logs in every test user first and keeps their tokens
def test_00_login_all_roles():
    _ensure_extra_test_users()
    STATE["tokens"], STATE["users"] = {}, {}
    for name in PASSWORDS:
        STATE["tokens"][name], STATE["users"][name] = login(name)


# registering works, and the same username or email twice gives 409
def test_register_public_regular_user():
    body = {"full_name": "Test Person", "username": f"tp_{RUN}", "email": f"tp_{RUN}@mail.com",
            "password": "Strong#Pass1", "department": "Finance", "role": "Regular Employee"}
    r = requests.post(f"{USERS}/users/register", json=body)
    assert r.status_code == 201, r.text
    data = r.json()["data"]
    assert "password" not in str(data).lower().replace("failed_login", "")
    assert data["email"] == f"tp_{RUN}@mail.com"
    STATE["new_user"] = data
    r = requests.post(f"{USERS}/users/register", json={**body, "email": f"other_{RUN}@mail.com"})
    assert r.status_code == 409 and "already taken" in r.json()["message"]
    r = requests.post(f"{USERS}/users/register", json={**body, "username": f"tp2_{RUN}",
                                                       "email": f"TP_{RUN}@MAIL.com"})
    assert r.status_code == 409


# looks in the database to make sure the password is hashed and the email encrypted
def test_password_hashed_and_email_encrypted_in_db():
    conn = sqlite3.connect(DATABASE_PATH)
    row = conn.execute("SELECT password_hash, email_encrypted FROM users WHERE username = ?",
                       (f"tp_{RUN}",)).fetchone()
    conn.close()
    assert row[0].startswith("$2b$") and "Strong#Pass1" not in row[0]
    assert f"tp_{RUN}" not in row[1]


# bad register inputs should all get a 400
def test_register_validation_errors():
    good = {"full_name": "Val Test", "username": f"val_{RUN}", "email": f"val_{RUN}@mail.com",
            "password": "Strong#Pass1", "department": "IT", "role": "Regular Employee"}
    cases = [
        ({**good, "email": "not-an-email"}, "Invalid email"),
        ({k: v for k, v in good.items() if k != "department"}, "Missing required"),
        ({**good, "password": "weak"}, "Password does not meet"),
        ({**good, "role": "Hacker"}, "Invalid role"),
        ({**good, "username": "x' OR '1'='1"}, "username"),
        ({**good, "full_name": "<script>alert(1)</script>"}, "full_name"),
        ({**good, "is_admin": True}, "Unexpected field"),
    ]
    for body, expected in cases:
        r = requests.post(f"{USERS}/users/register", json=body)
        assert r.status_code == 400, (body, r.text)
        assert r.json()["status"] == "error" and expected in r.json()["message"], r.text
    r = requests.post(f"{USERS}/users/register", data="not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 400
    r = requests.post(f"{USERS}/users/register", json={})
    assert r.status_code == 400


# only an admin can create an analyst account
def test_privileged_registration_rules():
    body = {"full_name": "New Analyst", "username": f"an_{RUN}", "email": f"an_{RUN}@mail.com",
            "password": "Strong#Pass1", "department": "SOC", "role": "Security Analyst"}
    assert requests.post(f"{USERS}/users/register", json=body).status_code == 403
    assert requests.post(f"{USERS}/users/register", json=body,
                         headers=H("analyst")).status_code == 403
    r = requests.post(f"{USERS}/users/register", json=body, headers=H("admin"))
    assert r.status_code == 201 and r.json()["data"]["role"] == "Security Analyst"
    STATE["new_analyst"] = r.json()["data"]


# good login, wrong password, unknown user and suspended account
def test_login_success_failure_and_status():
    r = requests.post(f"{USERS}/users/login", json={"username": "employee", "password": "wrong"})
    assert r.status_code == 401 and r.json()["message"] == "Invalid username/email or password"
    r = requests.post(f"{USERS}/users/login", json={"username": "nobody_x", "password": "wrong"})
    assert r.status_code == 401
    r = requests.post(f"{USERS}/users/login", json={"email": "employee@security.local",
                                                    "password": PASSWORDS["employee"]})
    assert r.status_code == 200 and r.json()["data"]["token_type"] == "Bearer"
    r = requests.post(f"{USERS}/users/login", json={"username": "suspended", "password": "Paused#Pass2026"})
    assert r.status_code == 403 and "suspended" in r.json()["message"]


# no token or a fake token should give 401
def test_protected_without_or_bad_token():
    assert requests.get(f"{USERS}/users").status_code == 401
    assert requests.get(f"{USERS}/users", headers={"Authorization": "Bearer abc.def.ghi"}).status_code == 401


# which roles are allowed to list all users
def test_get_users_permissions():
    assert requests.get(f"{USERS}/users", headers=H("admin")).status_code == 200
    r = requests.get(f"{USERS}/users", headers=H("auditor"))
    assert r.status_code == 200 and r.json()["total"] >= 5
    assert requests.get(f"{USERS}/users", headers=H("analyst")).status_code == 403
    assert requests.get(f"{USERS}/users", headers=H("employee")).status_code == 403


# getting a user by username for each role and for a missing user
def test_get_user_by_username():
    assert requests.get(f"{USERS}/users/employee", headers=H("admin")).status_code == 200
    assert requests.get(f"{USERS}/users/employee", headers=H("employee")).status_code == 200
    assert requests.get(f"{USERS}/users/admin", headers=H("employee")).status_code == 403
    assert requests.get(f"{USERS}/users/analyst", headers=H("analyst")).status_code == 403
    r = requests.get(f"{USERS}/users/doesnotexist_{RUN}", headers=H("auditor"))
    assert r.status_code == 404 and r.json()["status"] == "error"


# updates with good and bad permissions and bad data
def test_update_user():
    me = uid("employee")
    r = requests.put(f"{USERS}/users/{me}", json={"department": "Accounting"}, headers=H("employee"))
    assert r.status_code == 200 and r.json()["data"]["department"] == "Accounting"
    r = requests.put(f"{USERS}/users/{uid('employee2')}", json={"department": "X"}, headers=H("employee"))
    assert r.status_code == 403
    r = requests.put(f"{USERS}/users/{me}", json={"role": "Security Administrator"}, headers=H("employee"))
    assert r.status_code == 403
    r = requests.put(f"{USERS}/users/{me}", json={"email": "bad"}, headers=H("employee"))
    assert r.status_code == 400
    r = requests.put(f"{USERS}/users/{me}", json={"email": "admin@security.local"}, headers=H("employee"))
    assert r.status_code == 409
    assert requests.put(f"{USERS}/users/999999", json={"department": "IT"}, headers=H("admin")).status_code == 404
    assert requests.put(f"{USERS}/users/abc", json={"department": "IT"}, headers=H("admin")).status_code == 400
    assert requests.put(f"{USERS}/users/{me}", json={"department": "Finance"}, headers=H("auditor")).status_code == 403
    new_id = STATE["new_user"]["user_id"]
    r = requests.put(f"{USERS}/users/{new_id}", json={"role": "Auditor"}, headers=H("admin"))
    assert r.status_code == 200 and r.json()["data"]["role"] == "Auditor"
    r = requests.put(f"{USERS}/users/{uid('admin')}", json={"role": "Auditor"}, headers=H("admin"))
    assert r.status_code == 400


# once an account is suspended its token stops working
def test_suspended_user_token_stops_working():
    new_id = STATE["new_user"]["user_id"]
    tok, _ = login(f"tp_{RUN}", "Strong#Pass1")
    assert requests.get(f"{USERS}/users", headers=tok).status_code == 200
    requests.put(f"{USERS}/users/{new_id}", json={"account_status": "Suspended"}, headers=H("admin"))
    assert requests.get(f"{USERS}/users", headers=tok).status_code == 403
    requests.put(f"{USERS}/users/{new_id}", json={"account_status": "Active"}, headers=H("admin"))


# after logout the old token gets 401
def test_logout_revokes_token():
    tok, _ = login("employee2")
    assert requests.post(f"{USERS}/users/logout", headers=tok).status_code == 200
    r = requests.get(f"{USERS}/users/employee2", headers=tok)
    assert r.status_code == 401 and "revoked" in r.json()["message"]


# who can see the roles page
def test_roles_endpoint():
    r = requests.get(f"{USERS}/roles", headers=H("auditor"))
    assert r.status_code == 200 and "Security Administrator" in r.json()["data"]["permissions"]
    assert requests.get(f"{USERS}/roles", headers=H("employee")).status_code == 403


# internal routes refuse calls without the service key
def test_internal_endpoints_need_service_key():
    assert requests.get(f"{USERS}/internal/users/1").status_code == 403
    r = requests.get(f"{USERS}/internal/users/1", headers={"X-Service-Key": SERVICE_API_KEY})
    assert r.status_code == 200


# the earlier actions should have created logs on their own
def test_automatic_logs_were_created():
    time.sleep(0.5)
    r = requests.get(f"{AUDIT}/logs/search", params={"action": "LOGIN_FAILED"}, headers=H("admin"))
    assert r.status_code == 200 and r.json()["count"] >= 2
    for action in ("LOGIN_SUCCESS", "USER_CREATED", "ROLE_CHANGED", "UNAUTHORIZED_ACCESS",
                   "UNAUTHENTICATED_ACCESS", "LOGIN_BLOCKED", "USER_UPDATED", "LOGOUT"):
        r = requests.get(f"{AUDIT}/logs/search", params={"action": action}, headers=H("auditor"))
        assert r.json()["count"] >= 1, action


# creating a log, plus wrong roles and bad data getting refused
def test_create_log():
    body = {"user_id": uid("analyst"), "action": "incident created", "description": "Analyst opened incident #7",
            "severity": "information", "related_service": "Incidents"}
    r = requests.post(f"{AUDIT}/logs", json=body, headers=H("admin"))
    assert r.status_code == 201, r.text
    data = r.json()["data"]
    assert data["action"] == "INCIDENT_CREATED" and data["severity"] == "Information"
    assert data["integrity"] == "verified"
    STATE["log_id"] = data["log_id"]
    assert requests.post(f"{AUDIT}/logs", json=body, headers=H("auditor")).status_code == 403
    assert requests.post(f"{AUDIT}/logs", json=body, headers=H("analyst")).status_code == 403
    assert requests.post(f"{AUDIT}/logs", json={**body, "severity": "Huge"}, headers=H("admin")).status_code == 400
    assert requests.post(f"{AUDIT}/logs", json={**body, "user_id": 999999}, headers=H("admin")).status_code == 400
    assert requests.post(f"{AUDIT}/logs", json={**body, "related_service": "Nope"},
                         headers=H("admin")).status_code == 400
    r = requests.post(f"{AUDIT}/logs", json={k: v for k, v in body.items() if k != "description"},
                      headers=H("admin"))
    assert r.status_code == 400


# which roles can read the logs
def test_get_logs_permissions():
    assert requests.get(f"{AUDIT}/logs", headers=H("admin")).status_code == 200
    assert requests.get(f"{AUDIT}/logs", headers=H("auditor")).status_code == 200
    assert requests.get(f"{AUDIT}/logs", headers=H("analyst")).status_code == 403
    assert requests.get(f"{AUDIT}/logs", headers=H("employee")).status_code == 403
    lid = STATE["log_id"]
    for who in ("admin", "auditor", "analyst"):
        assert requests.get(f"{AUDIT}/logs/{lid}", headers=H(who)).status_code == 200
    assert requests.get(f"{AUDIT}/logs/{lid}", headers=H("employee")).status_code == 403
    assert requests.get(f"{AUDIT}/logs/999999", headers=H("admin")).status_code == 404
    assert requests.get(f"{AUDIT}/logs/abc", headers=H("admin")).status_code == 400


# log search filters and an sql injection attempt
def test_search_logs():
    today = time.strftime("%Y-%m-%d", time.gmtime())
    r = requests.get(f"{AUDIT}/logs/search", params={"user": "analyst", "date": today}, headers=H("analyst"))
    assert r.status_code == 200 and all(l["username"] == "analyst" for l in r.json()["data"])
    r = requests.get(f"{AUDIT}/logs/search", params={"severity": "Warning", "service": "Users"},
                     headers=H("auditor"))
    assert all(l["severity"] == "Warning" and l["related_service"] == "Users" for l in r.json()["data"])
    assert requests.get(f"{AUDIT}/logs/search", headers=H("admin")).status_code == 400
    assert requests.get(f"{AUDIT}/logs/search", params={"date": "17-10-2026"}, headers=H("admin")).status_code == 400
    assert requests.get(f"{AUDIT}/logs/search", params={"evil": "1"}, headers=H("admin")).status_code == 400
    r = requests.get(f"{AUDIT}/logs/search", params={"action": "'; DROP TABLE logs; --"}, headers=H("admin"))
    assert r.status_code == 200 and r.json()["count"] == 0
    assert requests.get(f"{AUDIT}/logs/search", params={"action": "LOGIN"}, headers=H("employee")).status_code == 403


# logs of one user and a user with no logs at all
def test_logs_by_user():
    r = requests.get(f"{AUDIT}/logs/user/{uid('analyst')}", headers=H("auditor"))
    assert r.status_code == 200 and r.json()["count"] >= 1
    assert all(l["user_id"] == uid("analyst") for l in r.json()["data"])
    r = requests.get(f"{AUDIT}/logs/user/987654", headers=H("admin"))
    assert r.status_code == 200 and r.json()["count"] == 0 and "No logs" in r.json()["message"]
    assert requests.get(f"{AUDIT}/logs/user/1", headers=H("analyst")).status_code == 403


# the database itself should refuse to edit a log
def test_logs_are_immutable_in_database():
    conn = sqlite3.connect(DATABASE_PATH)
    try:
        conn.execute("UPDATE logs SET action = 'HACKED' WHERE log_id = ?", (STATE["log_id"],))
        conn.commit()
        assert False, "update should have been blocked"
    except sqlite3.DatabaseError as exc:
        assert "immutable" in str(exc)
    finally:
        conn.close()


# only an admin can delete a log and the delete is logged too
def test_delete_log():
    lid = STATE["log_id"]
    assert requests.delete(f"{AUDIT}/logs/{lid}", headers=H("analyst")).status_code == 403
    assert requests.delete(f"{AUDIT}/logs/{lid}", headers=H("auditor")).status_code == 403
    assert requests.delete(f"{AUDIT}/logs/{lid}", headers=H("admin")).status_code == 200
    assert requests.get(f"{AUDIT}/logs/{lid}", headers=H("admin")).status_code == 404
    r = requests.get(f"{AUDIT}/logs/search", params={"action": "LOG_DELETED"}, headers=H("admin"))
    assert r.json()["count"] >= 1


# creating notifications as admin and as a service, and bad data getting refused
def test_create_notification():
    body = {"user_id": uid("analyst"), "title": "Incident assigned", "message": "Incident #7 is yours",
            "notification_type": "Incident Assignment", "severity": "High"}
    r = requests.post(f"{NOTIF}/notifications", json=body, headers=H("admin"))
    assert r.status_code == 201, r.text
    assert r.json()["data"]["status"] == "Unread" and r.json()["data"]["read_at"] is None
    STATE["notif_id"] = r.json()["data"]["notification_id"]
    assert requests.post(f"{NOTIF}/notifications", json=body, headers=H("analyst")).status_code == 403
    assert requests.post(f"{NOTIF}/notifications", json={**body, "user_id": 999999},
                         headers=H("admin")).status_code == 404
    assert requests.post(f"{NOTIF}/notifications", json={**body, "notification_type": "Spam"},
                         headers=H("admin")).status_code == 400
    assert requests.post(f"{NOTIF}/notifications", json={**body, "severity": "Extreme"},
                         headers=H("admin")).status_code == 400
    r = requests.post(f"{NOTIF}/notifications", headers={"X-Service-Key": SERVICE_API_KEY},
                      json={**body, "user_id": uid("employee"), "notification_type": "Security Alert"})
    assert r.status_code == 201


# the message should not be readable in the database
def test_notification_message_encrypted_in_db():
    conn = sqlite3.connect(DATABASE_PATH)
    row = conn.execute("SELECT message FROM notifications WHERE notification_id = ?",
                       (STATE["notif_id"],)).fetchone()
    conn.close()
    assert "Incident #7" not in row[0]


# a user's notifications for each role and the empty case
def test_user_notifications():
    r = requests.get(f"{NOTIF}/notifications/user/{uid('analyst')}", headers=H("analyst"))
    assert r.status_code == 200 and r.json()["count"] >= 1
    assert requests.get(f"{NOTIF}/notifications/user/{uid('analyst')}", headers=H("auditor")).status_code == 200
    assert requests.get(f"{NOTIF}/notifications/user/{uid('analyst')}", headers=H("employee")).status_code == 403
    r = requests.get(f"{NOTIF}/notifications/user/999999", headers=H("admin"))
    assert r.status_code == 404
    new_analyst = STATE["new_analyst"]["user_id"]
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("DELETE FROM notifications WHERE user_id = ?", (new_analyst,))
    conn.commit()
    conn.close()
    r = requests.get(f"{NOTIF}/notifications/user/{new_analyst}", headers=H("admin"))
    assert r.status_code == 200 and r.json()["count"] == 0 and "no notifications" in r.json()["message"]


# reading one notification for each role and a wrong id
def test_get_specific_notification():
    nid = STATE["notif_id"]
    assert requests.get(f"{NOTIF}/notifications/{nid}", headers=H("analyst")).status_code == 200
    assert requests.get(f"{NOTIF}/notifications/{nid}", headers=H("auditor")).status_code == 200
    assert requests.get(f"{NOTIF}/notifications/{nid}", headers=H("employee")).status_code == 403
    assert requests.get(f"{NOTIF}/notifications/999999", headers=H("admin")).status_code == 404


# marking as read, and the read date stays the same the second time
def test_mark_read():
    nid = STATE["notif_id"]
    assert requests.put(f"{NOTIF}/notifications/{nid}/read", headers=H("employee")).status_code == 403
    assert requests.put(f"{NOTIF}/notifications/{nid}/read", headers=H("auditor")).status_code == 403
    r = requests.put(f"{NOTIF}/notifications/{nid}/read", headers=H("analyst"))
    assert r.status_code == 200 and r.json()["data"]["status"] == "Read" and r.json()["data"]["read_at"]
    r2 = requests.put(f"{NOTIF}/notifications/{nid}/read", headers=H("analyst"))
    assert "already" in r2.json()["message"] and r2.json()["data"]["read_at"] == r.json()["data"]["read_at"]


# notification search filters for each role
def test_search_notifications():
    r = requests.get(f"{NOTIF}/notifications/search", params={"status": "Read"}, headers=H("analyst"))
    assert r.status_code == 200 and all(n["user_id"] == uid("analyst") for n in r.json()["data"])
    assert requests.get(f"{NOTIF}/notifications/search", params={"user_id": uid("employee")},
                        headers=H("analyst")).status_code == 403
    r = requests.get(f"{NOTIF}/notifications/search", params={"type": "System Notification", "severity": "low"},
                     headers=H("auditor"))
    assert r.status_code == 200 and r.json()["count"] >= 1
    assert requests.get(f"{NOTIF}/notifications/search", params={"status": "Maybe"},
                        headers=H("admin")).status_code == 400
    assert requests.get(f"{NOTIF}/notifications/search", headers=H("employee")).status_code == 403


# only an admin can delete a notification
def test_delete_notification():
    nid = STATE["notif_id"]
    assert requests.delete(f"{NOTIF}/notifications/{nid}", headers=H("analyst")).status_code == 403
    assert requests.delete(f"{NOTIF}/notifications/{nid}", headers=H("auditor")).status_code == 403
    assert requests.delete(f"{NOTIF}/notifications/{nid}", headers=H("admin")).status_code == 200
    assert requests.delete(f"{NOTIF}/notifications/{nid}", headers=H("admin")).status_code == 404


# the welcome and role change notifications should exist
def test_automatic_notifications():
    r = requests.get(f"{NOTIF}/notifications/user/{STATE['new_user']['user_id']}", headers=H("admin"))
    titles = [n["title"] for n in r.json()["data"]]
    assert any("Welcome" in t for t in titles) and any("role" in t for t in titles)


# 5 wrong passwords in a row create a critical log and alert the admins
def test_brute_force_alert():
    name = f"bf_{RUN}"
    requests.post(f"{USERS}/users/register", json={
        "full_name": "Brute Force", "username": name, "email": f"{name}@mail.com",
        "password": "Strong#Pass1", "department": "IT", "role": "Regular Employee"})
    for _ in range(5):
        requests.post(f"{USERS}/users/login", json={"username": name, "password": "Wrong#Pass1"})
    time.sleep(1.5)
    r = requests.get(f"{AUDIT}/logs/search", params={"action": "BRUTE_FORCE", "user": name}, headers=H("admin"))
    assert r.json()["count"] == 1 and r.json()["data"][0]["severity"] == "Critical"
    r = requests.get(f"{NOTIF}/notifications/search", params={"user_id": uid("admin"), "type": "Security Alert",
                                                               "severity": "Critical"}, headers=H("admin"))
    assert r.json()["count"] >= 1


# deleting a user keeps their logs
def test_delete_user_keeps_logs():
    victim = STATE["new_user"]
    assert requests.delete(f"{USERS}/users/{victim['user_id']}", headers=H("analyst")).status_code == 403
    assert requests.delete(f"{USERS}/users/{victim['user_id']}", headers=H("employee")).status_code == 403
    assert requests.delete(f"{USERS}/users/{uid('admin')}", headers=H("admin")).status_code == 400
    r = requests.delete(f"{USERS}/users/{victim['user_id']}", headers=H("admin"))
    assert r.status_code == 200
    assert requests.delete(f"{USERS}/users/{victim['user_id']}", headers=H("admin")).status_code == 404
    r = requests.get(f"{AUDIT}/logs/user/{victim['user_id']}", headers=H("auditor"))
    assert r.json()["count"] >= 1 and r.json()["user_exists"] is False
    assert all(l["integrity"] == "verified" for l in r.json()["data"])


# editing a log directly in the database should show TAMPERED
def test_tampering_detected():
    conn = sqlite3.connect(DATABASE_PATH)
    lid = conn.execute("SELECT MAX(log_id) FROM logs").fetchone()[0]
    conn.execute("DROP TRIGGER logs_are_immutable")
    conn.execute("UPDATE logs SET severity = 'Information', action = 'NOTHING_HAPPENED' WHERE log_id = ?", (lid,))
    conn.commit()
    conn.close()
    r = requests.get(f"{AUDIT}/logs/{lid}", headers=H("admin"))
    assert r.json()["data"]["integrity"] == "TAMPERED"
    from shared.db import init_db
    init_db()
    assert requests.delete(f"{AUDIT}/logs/{lid}", headers=H("admin")).status_code == 200
