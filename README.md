# Security Incident Detection and Response Management System – Sprint 1

| # | Service | Port | Folder | Base path | Student |
|---|---------|------|--------|-----------|---------|
| 1 | Users and Identity Management | 5001 | `user_service/` | `/users`, `/roles` | Reina Hani |
| 3 | Incident Management | 5003 | `incident_service/` | `/hayam-itani/incidents` | Hayam Itani |
| 4 | Threat Intelligence | 5004 | `threat_service/` | `/hayam-itani/threats` | Hayam Itani |
| 5 | Security Audit Logging | 5005 | `audit_service/` | `/logs` | Reina Hani |
| 8 | Notification and Alert Management | 5008 | `notification_service/` | `/notifications` | Reina Hani |
| 9 | Security Playbook and Response Automation | 5009 | `playbook_service/` | `/hayam-itani/playbooks`, `/hayam-itani/actions` | Hayam Itani |

Services 2 (Assets), 6 (Reports) and 7 (Vulnerabilities) are by Hamed Bou Saleh.

Full endpoint reference:
* Users, Audit Logging, Notifications: [`docs/API_DOCUMENTATION.md`](docs/API_DOCUMENTATION.md)
* Incidents, Threat Intelligence, Playbooks: [`docs/API_DOCUMENTATION_Incidents_Threats_Playbooks.md`](docs/API_DOCUMENTATION_Incidents_Threats_Playbooks.md)

---

## 1. Run it (Windows, PowerShell or CMD)

```powershell
cd 435L--sprint-1

# one-time setup
py -m venv venv
venv\Scripts\activate                 # PowerShell may need: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -r requirements.txt
python setup_env.py                   # creates .env with random secrets, asks your full name
python database\init_db.py            # creates database\security.db with all tables
python database\seed.py               # sample users (one per role)

# every time
python run_all.py                     # starts all the services, Ctrl+C stops them
```

You can also start each service in its own terminal, e.g. `python user_service\app.py`,
`python incident_service\app.py`, `python threat_service\app.py`, `python playbook_service\app.py`.

Check they are up: open http://127.0.0.1:5001/health, :5003/health, :5004/health, :5005/health,
:5008/health and :5009/health.

Always stop the services with **Ctrl+C** before closing the terminal; otherwise they keep running in the
background and the next start fails because the ports are still in use.

### Sample accounts

Created by `database/seed.py`:

| Username | Password | Role |
|---|---|---|
| admin | Admin@12345 | Security Administrator |
| analyst | Analyst@12345 | Security Analyst |
| employee | Employee@12345 | Regular Employee |
| auditor | Auditor@12345 | Auditor |

A second employee is needed to test "own records only" rules. The request **register user** in the
Incidents/Threats/Playbooks Postman collection creates `employee2` with the password `Second#Pass2026`
(a password may not contain the username).

### Test assets (until the Asset service is available)

Incidents need an existing asset. If the Asset service is not running yet, add three test assets:

```powershell
python -c "from shared.db import get_db; c = get_db(); c.executemany('INSERT INTO assets (asset_name, asset_type, ip_address, operating_system, owner_id, department, location, criticality_level, status) VALUES (?,?,?,?,?,?,?,?,?)', [('Finance laptop 07','Workstation','192.0.2.10','Windows 11',3,'Finance','Beirut HQ','Medium','Active'), ('Mail server','Server','192.0.2.20','Ubuntu 22.04',1,'IT Security','Data centre','High','Active'), ('Customer database','Database','192.0.2.30','PostgreSQL 16',1,'IT Security','Data centre','Critical','Active')]); c.commit()"
```

---

## 2. Test it

### Postman (for the report screenshots)

**Users, Audit Logging, Notifications**
1. Postman → **Import** → `postman/Sprint1_Users_Audit_Notifications.postman_collection.json`
2. Click the collection → **Variables** → set `student_name` to your full name, and `service_key`
   to the `SERVICE_API_KEY` value from your `.env`. Save.
3. Run folder **0. Authentication** first (logins store each role's token automatically).
4. Then run the other folders in order, or click **Run collection** to run all 101 requests
   (each one has tests that check the expected status code).

**Incidents, Threat Intelligence, Playbooks**
1. Postman → **Import** → `postman/Sprint1 - Incidents, Threats, and Playbooks (Hayam Itani).postman_collection.json`
   and `postman/Sprint1 local (Hayam Itani).postman_environment.json`.
2. Select the environment **Sprint1 local** (it holds the base URLs, e.g. `incidents_url` =
   `http://127.0.0.1:5003/hayam-itani`).
3. On a fresh database with the three test assets, run the folders in order: **Login**, **Incidents**,
   **Threats**, **Playbooks**. Every request has a description and a status-code test (135 requests).

The collections cover every API with success cases, validation errors (400), missing/invalid
token (401), wrong role (403), not found (404) and conflicts (409).

### Automated tests
With the Users, Audit Logging and Notification services running:
```powershell
pip install pytest
python -m pytest tests -v
```
32 end-to-end tests: every endpoint, every role, validation, encryption in the DB, the
immutability trigger, tamper detection, brute-force alerts, token revocation.

### Looking at the database (for "show the record in the database" screenshots)
Use **DB Browser for SQLite** (free) and open `database\security.db`. You will see:
`password_hash` = bcrypt hash, `email_encrypted`/`description`/`message` = encrypted text.
The API returns them decrypted.

---

## 3. Project structure

```
435L--sprint-1/
├── shared/                     code used by all services
│   ├── config.py               settings + secrets from .env, ports and URLs of every service
│   ├── db.py                   SQLite connection (foreign keys ON), schema creation, chmod 600
│   ├── security.py             bcrypt, Fernet encryption, HMAC, input validation/sanitization
│   ├── auth.py                 JWT login tokens, authentication, RBAC decorator, audit of violations
│   ├── permissions.py          RBAC matrix (which role can call which API, ALL or OWN scope)
│   ├── errors.py               uniform {"status": "error", "message": ...} responses
│   ├── app_factory.py          Flask app setup: error handlers, security headers, request size limit, logging
│   ├── service_client.py       HTTP client for service-to-service calls (X-Service-Key)
│   ├── audit_client.py         log_event(...)  -> POST /logs on the audit service
│   ├── notification_client.py  notify(...)     -> POST /notifications
│   └── user_client.py          get_user(...)   -> GET /internal/users/{id}
├── user_service/               Service 1: app.py, routes.py, repository.py, models.py
├── incident_service/           Service 3: app.py, routes.py, repository.py, models.py
├── threat_service/             Service 4: app.py, routes.py, repository.py, models.py, validators.py
├── audit_service/              Service 5
├── notification_service/       Service 8
├── playbook_service/           Service 9: app.py, routes.py, repository.py, models.py
├── database/schema.sql         all tables of the system + immutability trigger
├── database/init_db.py, seed.py
├── postman/                    collections and environment (+ build_collection.py)
├── tests/test_e2e.py
├── docs/API_DOCUMENTATION.md, docs/API_DOCUMENTATION_Incidents_Threats_Playbooks.md
├── run_all.py, setup_env.py, backup_db.py, generate_cert.py
└── requirements.txt, .gitignore
```

Each service follows the same layers (OOP):
**routes** (HTTP + validation + permission checks) → **repository** class (SQL) → **model** class
(row → object, decryption, `to_dict()` that never exposes secrets).

---

## 4. What was implemented and how

### Authentication (JWT)
* `POST /users/login` checks the username **or** email and the password with `bcrypt.checkpw`,
  then returns a JWT signed with `JWT_SECRET` (HS256), valid 60 min, containing user id, username,
  role and a unique id (`jti`).
* Clients send `Authorization: Bearer <token>`. Every service verifies signature + expiry, checks the
  token was not revoked (`POST /users/logout` stores the `jti` in `revoked_tokens`), and reloads the
  user from the database: a deleted, suspended or re-roled user is affected **immediately**.
* Inactive and Suspended users cannot log in (403) and their existing tokens stop working.
* Unknown usernames get the same message and the same response time as wrong passwords (a dummy
  bcrypt check runs), so attackers cannot discover valid usernames.
* 5 consecutive failed logins → `BRUTE_FORCE_SUSPECTED` **Critical** log + Security Alert notification
  to the user + Security Alert to every administrator.

### Authorization (RBAC)
`shared/permissions.py` is one table: permission → roles → scope (`all` or `own`).
Each route has `@require_permission("logs:delete")`, for example. Rules from the project document:

| API | Admin | Analyst | Employee | Auditor |
|---|---|---|---|---|
| POST /users/register | Yes, any role | No | Yes (Regular only, also anonymous) | No |
| PUT /users/{id} | Yes (+ role, status) | No | own only | No |
| DELETE /users/{id} | Yes | No | No | No |
| GET /users | Yes | No | No | Yes |
| GET /users/{username} | Yes | No | own only | Yes |
| POST /logs | Yes | No | No | No |
| GET /logs | Yes | No | No | Yes |
| GET /logs/{id}, /logs/search | Yes | Yes | No | Yes |
| DELETE /logs/{id} | Yes | No | No | No |
| GET /logs/user/{id} | Yes | No | No | Yes |
| POST /notifications | Yes | No | No | No |
| GET /notifications/user/{id}, /{id} | Yes | own | own | Yes |
| PUT /notifications/{id}/read | Yes | own | own | No (read-only) |
| GET /notifications/search | Yes | own | No | Yes |
| DELETE /notifications/{id} | Yes | No | No | No |
| POST /hayam-itani/incidents | Yes | No | Yes | No |
| GET /hayam-itani/incidents, /{id} | Yes | assigned only | reported only | Yes |
| PUT /hayam-itani/incidents/{id}/assign | Yes | No | No | No |
| PUT /hayam-itani/incidents/{id}/status | Yes (only admins close) | assigned only | No | No |
| POST /hayam-itani/incidents/{id}/notes | Yes | assigned only | No | No |
| POST, PUT, DELETE /hayam-itani/threats... | Yes | No | No | No |
| GET /hayam-itani/threats, /{id}, /search | Yes | Yes | No | Yes |
| POST, DELETE /hayam-itani/playbooks... | Yes | No | No | No |
| GET /hayam-itani/playbooks, /{id} | Yes | Yes | No | Yes |
| POST /hayam-itani/playbooks/{id}/actions | Yes | Yes | No | No |
| PUT /hayam-itani/actions/{id}/status | Yes | Yes | No | No |

Every rejected attempt returns `403 {"status":"error","message":"User does not have permission to
perform this operation"}` **and** is stored as an `UNAUTHORIZED_ACCESS` log (Warning).
Requests with no/invalid/expired token return 401 and are stored as `UNAUTHENTICATED_ACCESS`.

### Communication between services (REST API calls)
* Every service writes audit events by calling `POST /logs` on the audit service.
* The notification service calls `GET /internal/users/{id}` on the users service to check that the
  recipient exists.
* The users service calls `POST /notifications` (welcome, role change, status change, brute force).
* The audit service calls `GET /internal/users?role=Security Administrator` then `POST /notifications`
  to alert all admins of every **Critical** log.
* The incident service calls `GET /internal/users/{id}` to check that an incident is assigned to an
  active Security Analyst, then `POST /notifications` (Incident Assignment). A Critical incident sends a
  Security Alert to every administrator.
* The threat service calls `GET /internal/users?role=Security Analyst` and `POST /notifications` to send a
  Threat Alert to every analyst when a High or Critical indicator is added.
* The playbook service calls `GET /internal/users/{id}` to check the user a response step is assigned to,
  then notifies that user.
* Service-to-service calls carry `X-Service-Key` (compared in constant time). `/internal/*` endpoints
  refuse anything else. If a service is down, the caller keeps working and writes the event to its
  local log file.

### Incidents, Threat Intelligence and Playbooks
* **Incident lifecycle:** Open → Under Investigation → Mitigated → Resolved → Closed, one step at a time.
  Skipping a step or going back returns 400 and is logged as `INVALID_STATUS_TRANSITION`. An incident
  needs an assigned analyst before it goes Under Investigation, and only an administrator closes it.
  `resolved_at` is set when it becomes Resolved; notes cannot be added to a closed incident.
* **Own records:** analysts only see and update the incidents assigned to them; employees only see the
  incidents they reported.
* **Threat indicators:** the value is checked against its type (IPv4/IPv6 address, domain name, MD5/SHA-1/
  SHA-256 hash) and normalised to lower case. `UNIQUE (threat_type, threat_value)` prevents duplicates (409).
  Only the description, severity and source can be updated. Search supports type, value (partial),
  severity and source (partial); `%` and `_` in search text are escaped.
* **Playbooks:** response actions are ordered by `step_number` (unique per playbook). A step moves
  Pending → In Progress → Completed, cannot start while an earlier step is unfinished, and cannot change
  once completed. Deleting a playbook deletes its actions (`ON DELETE CASCADE`).

### Lab 2 security measures – where each one is
| Lab 2 item | Implementation |
|---|---|
| 1. Prevent SQL injection | Only parameterized queries (`?`) in every repository; search filters use fixed column names; tested with `' OR '1'='1` and `'; DROP TABLE logs; --` |
| 2. Input validation & sanitization | `shared/security.py`: type checks, `strip()`, required fields, unknown fields rejected, email/username regex, allowed-value lists, control characters and `<`/`>` rejected, empty/invalid JSON rejected, 16 KB body limit |
| 3. Encryption of sensitive data | **Fernet** (`cryptography`): user emails, audit-log descriptions and notification messages are encrypted in the DB. Passwords are **bcrypt-hashed** (one-way, as the project requires). Keys live in `.env`, not in the code |
| 4. Database file permissions | `chmod 600` applied to the DB and backups on creation (`shared/db.py`). On Windows also run: `icacls database\security.db /inheritance:r /grant:r "%USERNAME%:F"` |
| 5. Limit DB permissions | Audit logs: a trigger forbids UPDATE; only admins can delete through the API; each service only touches its own tables |
| 6. Limit input length | Every text field has a max length (name 100, title 150, description 1000, message 2000…) |
| 7. Prepared statements | Same as 1 – `sqlite3` parameter binding |
| 8. Backups | `python backup_db.py` (SQLite online-backup API, keeps last 10). Automate with Windows Task Scheduler |
| 9. Logging & monitoring | Audit service in the DB + local rotating files `logs/<service>.log` |
| 10. Exception handling | Global handlers: DB errors and crashes return a generic 500 message; details only go to the log file |
| 11. HTTPS | `python generate_cert.py`, then `USE_HTTPS=true` in `.env`: all services serve HTTPS and verify each other's certificate |
| 12. Updates | Pinned versions in `requirements.txt`; update with `pip install --upgrade -r requirements.txt` |

Extra protections: email "blind index" (HMAC-SHA256) to search encrypted emails, HMAC integrity
signature on every audit log (`"integrity": "verified"` or `"TAMPERED"` in responses), security
headers (`X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control: no-store`), Flask debug mode
off by default, password policy (8+ chars, upper, lower, digit, special, not containing username).

### Audit log protection
* No update endpoint exists, and the `logs_are_immutable` trigger aborts any SQL `UPDATE` on the table.
* When a user is deleted, the foreign key sets `user_id` to NULL (the only change the trigger allows),
  while `original_user_id` and `actor_username` keep the history, so `GET /logs/user/{id}` still works.
* Deleting a log (admin only) creates a `LOG_DELETED` log.

### Automatically generated logs
`LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGIN_BLOCKED`, `BRUTE_FORCE_SUSPECTED`, `LOGOUT`, `USER_CREATED`,
`ROLE_ASSIGNED`, `USER_UPDATED`, `ROLE_CHANGED`, `ACCOUNT_STATUS_CHANGED`, `USER_DELETED`,
`UNAUTHORIZED_ACCESS`, `UNAUTHENTICATED_ACCESS`, `NOTIFICATION_CREATED`, `NOTIFICATION_READ`,
`NOTIFICATION_DELETED`, `LOG_DELETED`, `INCIDENT_CREATED`, `INCIDENT_ASSIGNED`,
`INCIDENT_STATUS_CHANGED`, `INVALID_STATUS_TRANSITION`, `INCIDENT_NOTE_ADDED`, `THREAT_CREATED`,
`THREAT_UPDATED`, `THREAT_DELETED`, `PLAYBOOK_CREATED`, `RESPONSE_ACTION_ADDED`,
`RESPONSE_ACTION_UPDATED`, `PLAYBOOK_DELETED`.

### For teammates
* All tables are in `database/schema.sql` (one shared database with real foreign keys).
* To log from your service: `from shared.audit_client import log_event`
* To notify (incident assignment, threat/vulnerability alerts): `from shared.notification_client import notify`
* To protect a route: add your permissions to `shared/permissions.py` and use `@require_permission(...)`.
* To put your name in your URLs: `Blueprint("name", __name__, url_prefix="/your-name")`.

---

## 5. GitHub
`.gitignore` excludes `.env`, the database, logs, backups and certificates — secrets never reach GitHub.
Each member works on their own branch (`reina-services`, `hayam-services`, …) and merges into `main`
through a pull request.
