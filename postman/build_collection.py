"""
Generates the Postman collection JSON:
    python postman/build_collection.py
Import the produced file in Postman (File -> Import). Run "0. Authentication" first:
the login requests save each role's token in collection variables automatically.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "Sprint1_Users_Audit_Notifications.postman_collection.json")

U, A, N = "{{users_url}}", "{{audit_url}}", "{{notifications_url}}"


def req(name, method, url, token=None, body=None, expect=200, desc="", save=None, headers=None,
        pre=None, extra_tests=None):
    hdrs = [{"key": "Content-Type", "value": "application/json"}] if body is not None else []
    if token:
        hdrs.append({"key": "Authorization", "value": "Bearer {{token_%s}}" % token})
    for k, v in (headers or {}).items():
        hdrs.append({"key": k, "value": v})
    tests = [
        f"pm.test('Status code is {expect}', function () {{ pm.response.to.have.status({expect}); }});",
        "pm.test('Response has a status field', function () { pm.expect(pm.response.json()).to.have.property('status'); });",
    ]
    for var, path in (save or {}).items():
        tests.append(f"if (pm.response.code < 300) {{ pm.collectionVariables.set('{var}', pm.response.json().{path}); }}")
    tests += extra_tests or []
    raw_url = url
    item = {
        "name": name,
        "event": [{"listen": "test", "script": {"type": "text/javascript", "exec": tests}}],
        "request": {
            "method": method,
            "header": hdrs,
            "url": raw_url,
            "description": f"**Student:** {{{{student_name}}}}\n\n{desc}\n\nExpected HTTP status: {expect}",
        },
    }
    if pre:
        item["event"].append({"listen": "prerequest", "script": {"type": "text/javascript", "exec": pre}})
    if body is not None:
        item["request"]["body"] = {"mode": "raw", "raw": json.dumps(body, indent=2),
                                   "options": {"raw": {"language": "json"}}}
    return item


def login(role, username, password):
    return req(f"Login as {role} ({username})", "POST", f"{U}/users/login",
               body={"username": username, "password": password},
               desc=f"Authenticates **{username}** and stores the JWT in `token_{role}`.",
               save={f"token_{role}": "data.token", f"{role}_id": "data.user.user_id"})


auth = [
    login("admin", "admin", "Admin@12345"),
    login("analyst", "analyst", "Analyst@12345"),
    login("employee", "employee", "Employee@12345"),
    login("employee2", "employee2", "Employee2@12345"),
    login("auditor", "auditor", "Auditor@12345"),
    req("Login with email instead of username", "POST", f"{U}/users/login",
        body={"email": "employee@security.local", "password": "Employee@12345"},
        desc="The API accepts a username OR an email."),
    req("Failed login - wrong password", "POST", f"{U}/users/login",
        body={"username": "employee", "password": "WrongPassword1!"}, expect=401,
        desc="Wrong password -> 401 and a LOGIN_FAILED audit log (Warning)."),
    req("Failed login - unknown user", "POST", f"{U}/users/login",
        body={"username": "ghost_user", "password": "Whatever1!"}, expect=401,
        desc="Same generic message as a wrong password, so attackers cannot discover usernames."),
    req("Login blocked - suspended account", "POST", f"{U}/users/login",
        body={"username": "suspended", "password": "Suspended@12345"}, expect=403,
        desc="Inactive / Suspended users cannot authenticate (LOGIN_BLOCKED log)."),
    req("Login - missing fields (validation)", "POST", f"{U}/users/login", body={"username": "admin"},
        expect=400),
]

rand_pre = ["pm.collectionVariables.set('rand', Date.now().toString().slice(-7));"]

users = [
    req("Register user (public, Regular Employee)", "POST", f"{U}/users/register",
        body={"full_name": "Maya Haddad", "username": "maya{{rand}}", "email": "maya{{rand}}@company.com",
              "password": "Secure#Pass2026", "department": "Finance", "role": "Regular Employee"},
        expect=201, pre=rand_pre, save={"new_user_id": "data.user_id", "new_username": "data.username"},
        desc="Anyone can self-register as a Regular Employee. Password is bcrypt-hashed; email is "
             "Fernet-encrypted in the database."),
    req("Register - duplicate username (409)", "POST", f"{U}/users/register",
        body={"full_name": "Maya Copy", "username": "{{new_username}}", "email": "copy{{rand}}@company.com",
              "password": "Secure#Pass2026", "department": "Finance", "role": "Regular Employee"},
        expect=409, desc="Username uniqueness is checked before insert and enforced by a UNIQUE constraint."),
    req("Register - invalid email (400)", "POST", f"{U}/users/register",
        body={"full_name": "Bad Email", "username": "bademail{{rand}}", "email": "not-an-email",
              "password": "Secure#Pass2026", "department": "IT", "role": "Regular Employee"}, expect=400),
    req("Register - weak password (400)", "POST", f"{U}/users/register",
        body={"full_name": "Weak Pass", "username": "weak{{rand}}", "email": "weak{{rand}}@company.com",
              "password": "12345", "department": "IT", "role": "Regular Employee"}, expect=400),
    req("Register - missing fields (400)", "POST", f"{U}/users/register",
        body={"username": "incomplete{{rand}}"}, expect=400),
    req("Register - SQL injection attempt in username (400)", "POST", f"{U}/users/register",
        body={"full_name": "Injector", "username": "x' OR '1'='1", "email": "inj{{rand}}@company.com",
              "password": "Secure#Pass2026", "department": "IT", "role": "Regular Employee"}, expect=400),
    req("Register - anonymous tries to create an Admin (403)", "POST", f"{U}/users/register",
        body={"full_name": "Evil Admin", "username": "evil{{rand}}", "email": "evil{{rand}}@company.com",
              "password": "Secure#Pass2026", "department": "IT", "role": "Security Administrator"},
        expect=403, desc="Only an authenticated administrator may assign privileged roles. "
                         "The attempt is logged as UNAUTHORIZED_ACCESS."),
    req("Register - Admin creates a Security Analyst", "POST", f"{U}/users/register", token="admin",
        body={"full_name": "Karim Nassar", "username": "karim{{rand}}", "email": "karim{{rand}}@company.com",
              "password": "Analyst#Pass2026", "department": "SOC", "role": "Security Analyst"},
        expect=201, save={"new_analyst_id": "data.user_id"}),
    req("Get all users (Admin)", "GET", f"{U}/users", token="admin"),
    req("Get all users (Auditor)", "GET", f"{U}/users?limit=50&offset=0", token="auditor"),
    req("Get all users - Analyst denied (403)", "GET", f"{U}/users", token="analyst", expect=403),
    req("Get all users - no token (401)", "GET", f"{U}/users", expect=401),
    req("Get user by username (Admin)", "GET", f"{U}/users/{{{{new_username}}}}", token="admin"),
    req("Get own profile (Employee)", "GET", f"{U}/users/employee", token="employee"),
    req("Get another user's profile - Employee denied (403)", "GET", f"{U}/users/admin", token="employee",
        expect=403),
    req("Get user by username - not found (404)", "GET", f"{U}/users/nobody_here", token="auditor", expect=404),
    req("Update own info (Employee)", "PUT", f"{U}/users/{{{{employee_id}}}}", token="employee",
        body={"department": "Accounting", "full_name": "Omar Employee"}),
    req("Update another user - Employee denied (403)", "PUT", f"{U}/users/{{{{employee2_id}}}}",
        token="employee", body={"department": "Hacked"}, expect=403),
    req("Update own role - Employee denied (403)", "PUT", f"{U}/users/{{{{employee_id}}}}",
        token="employee", body={"role": "Security Administrator"}, expect=403),
    req("Update - invalid email (400)", "PUT", f"{U}/users/{{{{employee_id}}}}", token="employee",
        body={"email": "wrong-format"}, expect=400),
    req("Admin updates user info", "PUT", f"{U}/users/{{{{new_user_id}}}}", token="admin",
        body={"full_name": "Maya Haddad-Khoury", "email": "maya.k{{rand}}@company.com", "department": "Risk"}),
    req("Admin changes user role (ROLE_CHANGED log + notification)", "PUT", f"{U}/users/{{{{new_user_id}}}}",
        token="admin", body={"role": "Auditor"}),
    req("Admin suspends a user", "PUT", f"{U}/users/{{{{new_user_id}}}}", token="admin",
        body={"account_status": "Suspended"}),
    req("Admin re-activates the user", "PUT", f"{U}/users/{{{{new_user_id}}}}", token="admin",
        body={"account_status": "Active"}),
    req("Update - user not found (404)", "PUT", f"{U}/users/999999", token="admin",
        body={"department": "IT"}, expect=404),
    req("View roles and permissions (Admin)", "GET", f"{U}/roles", token="admin"),
    req("Delete user - Analyst denied (403)", "DELETE", f"{U}/users/{{{{new_user_id}}}}", token="analyst",
        expect=403),
    req("Delete user - Employee denied (403)", "DELETE", f"{U}/users/{{{{new_user_id}}}}", token="employee",
        expect=403),
    req("Delete user (Admin)", "DELETE", f"{U}/users/{{{{new_user_id}}}}", token="admin",
        desc="Deletes the user. Their audit logs are kept (user_id set to NULL, original_user_id preserved); "
             "their notifications are deleted (ON DELETE CASCADE)."),
    req("Delete user - already deleted (404)", "DELETE", f"{U}/users/{{{{new_user_id}}}}", token="admin",
        expect=404),
    req("Internal: get user with service key", "GET", f"{U}/internal/users/1",
        headers={"X-Service-Key": "{{service_key}}"},
        desc="Service-to-service endpoint. Put the SERVICE_API_KEY value from .env in the `service_key` "
             "collection variable."),
    req("Internal: without service key (403)", "GET", f"{U}/internal/users/1", expect=403),
]

logs = [
    req("Create log record (Admin)", "POST", f"{A}/logs", token="admin",
        body={"user_id": "{{analyst_id}}", "action": "INCIDENT_CREATED",
              "description": "Analyst opened incident #12 (phishing campaign)", "severity": "Information",
              "related_service": "Incidents"}, expect=201, save={"log_id": "data.log_id"}),
    req("Create log record - Warning", "POST", f"{A}/logs", token="admin",
        body={"user_id": "{{employee_id}}", "action": "ASSET_MODIFIED",
              "description": "Workstation WS-22 owner changed", "severity": "Warning",
              "related_service": "Assets"}, expect=201),
    req("Create log record - Critical (alerts all admins)", "POST", f"{A}/logs", token="admin",
        body={"user_id": "{{admin_id}}", "action": "THREAT_DETECTED",
              "description": "Ransomware hash detected on FS-01", "severity": "Critical",
              "related_service": "Threat Intelligence"}, expect=201,
        desc="Critical logs automatically send a Security Alert notification to every active administrator."),
    req("Create log - invalid severity (400)", "POST", f"{A}/logs", token="admin",
        body={"user_id": "{{admin_id}}", "action": "TEST", "description": "bad severity",
              "severity": "Super", "related_service": "Users"}, expect=400),
    req("Create log - missing fields (400)", "POST", f"{A}/logs", token="admin",
        body={"action": "TEST"}, expect=400),
    req("Create log - Auditor denied (403)", "POST", f"{A}/logs", token="auditor",
        body={"user_id": "{{admin_id}}", "action": "TEST", "description": "auditor is read only",
              "severity": "Information", "related_service": "Users"}, expect=403),
    req("Create log via service key", "POST", f"{A}/logs", headers={"X-Service-Key": "{{service_key}}"},
        body={"user_id": None, "action": "SYSTEM_STARTUP", "description": "Scheduled integrity check",
              "severity": "Information", "related_service": "Audit Logging"}, expect=201),
    req("Get all logs (Admin)", "GET", f"{A}/logs?limit=20", token="admin"),
    req("Get all logs (Auditor)", "GET", f"{A}/logs", token="auditor"),
    req("Get all logs - Analyst denied (403)", "GET", f"{A}/logs", token="analyst", expect=403),
    req("Get all logs - Employee denied (403)", "GET", f"{A}/logs", token="employee", expect=403),
    req("Get specific log (Analyst)", "GET", f"{A}/logs/{{{{log_id}}}}", token="analyst"),
    req("Get specific log - not found (404)", "GET", f"{A}/logs/999999", token="admin", expect=404),
    req("Get specific log - invalid id (400)", "GET", f"{A}/logs/abc", token="admin", expect=400),
    req("Search logs by action", "GET", f"{A}/logs/search?action=LOGIN_FAILED", token="auditor"),
    req("Search logs by user + severity", "GET", f"{A}/logs/search?user=employee&severity=Warning",
        token="admin"),
    req("Search logs by service + date range", "GET",
        f"{A}/logs/search?service=Users&date_from=2026-01-01&date_to=2026-12-31", token="analyst"),
    req("Search logs by exact date", "GET", f"{A}/logs/search?date={{{{today}}}}", token="admin",
        pre=["pm.collectionVariables.set('today', new Date().toISOString().slice(0,10));"]),
    req("Search logs - no criteria (400)", "GET", f"{A}/logs/search", token="admin", expect=400),
    req("Search logs - bad date format (400)", "GET", f"{A}/logs/search?date=17/10/2026", token="admin",
        expect=400),
    req("Search logs - Employee denied (403)", "GET", f"{A}/logs/search?action=LOGIN", token="employee",
        expect=403),
    req("Logs by user (Auditor)", "GET", f"{A}/logs/user/{{{{employee_id}}}}", token="auditor"),
    req("Logs by user - user with no logs", "GET", f"{A}/logs/user/987654", token="admin",
        desc="Returns 200 with an empty list and count 0."),
    req("Logs by user - Analyst denied (403)", "GET", f"{A}/logs/user/{{{{employee_id}}}}", token="analyst",
        expect=403),
    req("Delete log - Analyst denied (403)", "DELETE", f"{A}/logs/{{{{log_id}}}}", token="analyst", expect=403),
    req("Delete log - Auditor denied (403)", "DELETE", f"{A}/logs/{{{{log_id}}}}", token="auditor", expect=403),
    req("Delete log (Admin)", "DELETE", f"{A}/logs/{{{{log_id}}}}", token="admin",
        desc="The deletion itself is recorded as a LOG_DELETED log."),
    req("Delete log - not found (404)", "DELETE", f"{A}/logs/{{{{log_id}}}}", token="admin", expect=404),
]

notifications = [
    req("Create notification - Incident Assignment", "POST", f"{N}/notifications", token="admin",
        body={"user_id": "{{analyst_id}}", "title": "New incident assigned",
              "message": "Incident #12 (phishing) has been assigned to you.",
              "notification_type": "Incident Assignment", "severity": "High"},
        expect=201, save={"notification_id": "data.notification_id"}),
    req("Create notification - Threat Alert", "POST", f"{N}/notifications", token="admin",
        body={"user_id": "{{analyst_id}}", "title": "Malicious IP observed",
              "message": "185.220.101.4 matched a threat indicator.",
              "notification_type": "Threat Alert", "severity": "Critical"}, expect=201),
    req("Create notification - Vulnerability Alert", "POST", f"{N}/notifications", token="admin",
        body={"user_id": "{{employee_id}}", "title": "Patch required",
              "message": "Your workstation is affected by CVE-2024-3400.",
              "notification_type": "Vulnerability Alert", "severity": "Medium"}, expect=201),
    req("Create notification via service key", "POST", f"{N}/notifications",
        headers={"X-Service-Key": "{{service_key}}"},
        body={"user_id": "{{employee_id}}", "title": "Security awareness",
              "message": "Remember to report suspicious emails.", "notification_type": "Security Alert",
              "severity": "Low"}, expect=201),
    req("Create notification - unknown user (404)", "POST", f"{N}/notifications", token="admin",
        body={"user_id": 999999, "title": "Nobody", "message": "x", "notification_type": "Security Alert",
              "severity": "Low"}, expect=404,
        desc="The Notification service asks the Users service (API call) whether the user exists."),
    req("Create notification - invalid type (400)", "POST", f"{N}/notifications", token="admin",
        body={"user_id": "{{analyst_id}}", "title": "Bad type", "message": "x",
              "notification_type": "Spam", "severity": "Low"}, expect=400),
    req("Create notification - Analyst denied (403)", "POST", f"{N}/notifications", token="analyst",
        body={"user_id": "{{analyst_id}}", "title": "Self", "message": "x",
              "notification_type": "Security Alert", "severity": "Low"}, expect=403),
    req("Get my notifications (Analyst)", "GET", f"{N}/notifications/user/{{{{analyst_id}}}}", token="analyst"),
    req("Get my unread notifications (Employee)", "GET",
        f"{N}/notifications/user/{{{{employee_id}}}}?status=Unread", token="employee"),
    req("Get user notifications (Auditor)", "GET", f"{N}/notifications/user/{{{{analyst_id}}}}", token="auditor"),
    req("Get user notifications - empty result", "GET",
        f"{N}/notifications/user/{{{{new_analyst_id}}}}?status=Read", token="admin",
        desc="The new analyst has never read a notification, so the list is empty (count 0, HTTP 200)."),
    req("Get another user's notifications - Employee denied (403)", "GET",
        f"{N}/notifications/user/{{{{analyst_id}}}}", token="employee", expect=403),
    req("Get user notifications - user not found (404)", "GET", f"{N}/notifications/user/999999",
        token="admin", expect=404),
    req("Get specific notification (owner)", "GET", f"{N}/notifications/{{{{notification_id}}}}",
        token="analyst"),
    req("Get specific notification - not owner (403)", "GET", f"{N}/notifications/{{{{notification_id}}}}",
        token="employee", expect=403),
    req("Get specific notification - not found (404)", "GET", f"{N}/notifications/999999", token="admin",
        expect=404),
    req("Mark as read - Auditor denied (403)", "PUT", f"{N}/notifications/{{{{notification_id}}}}/read",
        token="auditor", expect=403),
    req("Mark as read - not owner (403)", "PUT", f"{N}/notifications/{{{{notification_id}}}}/read",
        token="employee", expect=403),
    req("Mark as read (owner)", "PUT", f"{N}/notifications/{{{{notification_id}}}}/read", token="analyst",
        desc="status Unread -> Read and read_at is set."),
    req("Mark as read - already read", "PUT", f"{N}/notifications/{{{{notification_id}}}}/read",
        token="analyst", desc="Idempotent: returns 200 and keeps the original read_at."),
    req("Search notifications by type + severity (Auditor)", "GET",
        f"{N}/notifications/search?type=Threat Alert&severity=Critical", token="auditor"),
    req("Search notifications by user + status (Admin)", "GET",
        f"{N}/notifications/search?user_id={{{{analyst_id}}}}&status=Read", token="admin"),
    req("Search own notifications (Analyst)", "GET", f"{N}/notifications/search?status=Unread",
        token="analyst", desc="Analysts are automatically restricted to their own notifications."),
    req("Search other user's notifications - Analyst denied (403)", "GET",
        f"{N}/notifications/search?user_id={{{{employee_id}}}}", token="analyst", expect=403),
    req("Search notifications - invalid status (400)", "GET", f"{N}/notifications/search?status=Maybe",
        token="admin", expect=400),
    req("Search notifications - Employee denied (403)", "GET", f"{N}/notifications/search", token="employee",
        expect=403),
    req("Delete notification - Analyst denied (403)", "DELETE", f"{N}/notifications/{{{{notification_id}}}}",
        token="analyst", expect=403),
    req("Delete notification (Admin)", "DELETE", f"{N}/notifications/{{{{notification_id}}}}", token="admin"),
    req("Delete notification - not found (404)", "DELETE", f"{N}/notifications/{{{{notification_id}}}}",
        token="admin", expect=404),
]

logout = [
    req("Logout (Employee2) - revokes the token", "POST", f"{U}/users/logout", token="employee2"),
    req("Use revoked token (401)", "GET", f"{U}/users/employee2", token="employee2", expect=401),
]

collection = {
    "info": {
        "name": "Sprint 1 - Users, Audit Logging, Notifications",
        "description": "Security Incident Detection and Response Management System.\n"
                       "Services: Users (5001), Security Audit Logging (5005), Notifications (5008).\n"
                       "Run folder 0 first; tokens are stored automatically. Set `student_name` and "
                       "`service_key` (SERVICE_API_KEY from .env) in the collection variables.",
        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    "item": [
        {"name": "0. Authentication (run first)", "item": auth},
        {"name": "1. Users and Identity Management (5001)", "item": users},
        {"name": "5. Security Audit Logging (5005)", "item": logs},
        {"name": "8. Notifications and Alerts (5008)", "item": notifications},
        {"name": "9. Logout / token revocation", "item": logout},
    ],
    "variable": [
        {"key": "users_url", "value": "http://127.0.0.1:5001"},
        {"key": "audit_url", "value": "http://127.0.0.1:5005"},
        {"key": "notifications_url", "value": "http://127.0.0.1:5008"},
        {"key": "student_name", "value": "<Your Full Name>"},
        {"key": "service_key", "value": "PASTE_SERVICE_API_KEY_FROM_.env"},
    ] + [{"key": k, "value": ""} for k in (
        "token_admin", "token_analyst", "token_employee", "token_employee2", "token_auditor",
        "admin_id", "analyst_id", "employee_id", "employee2_id", "auditor_id",
        "new_user_id", "new_username", "new_analyst_id", "log_id", "notification_id", "rand", "today")],
}

with open(OUT, "w", encoding="utf-8") as f:
    json.dump(collection, f, indent=2)
print(f"Wrote {OUT} ({sum(len(g['item']) for g in collection['item'])} requests)")
