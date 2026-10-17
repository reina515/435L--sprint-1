# Security Incident Detection and Response Management System – Sprint 1

My services:

| # | Service | Port | Folder |
|---|---------|------|--------|
| 1 | Users and Identity Management | 5001 | `user_service/` |
| 5 | Security Audit Logging | 5005 | `audit_service/` |
| 8 | Notification and Alert Management | 5008 | `notification_service/` |

Full endpoint reference: [`docs/API_DOCUMENTATION.md`](docs/API_DOCUMENTATION.md)

---

## 1. Run it (Windows, PowerShell or CMD)

```powershell
cd "C:\Users\ASUS\Desktop\Fall E4\EECE 435L\sprint1"

# one-time setup
py -m venv venv
venv\Scripts\activate                 # PowerShell may need: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -r requirements.txt
python setup_env.py                   # creates .env with random secrets, asks your full name
python database\init_db.py            # creates database\security.db with all tables
python database\seed.py               # sample users (one per role)

# every time
python run_all.py                     # starts the 3 services, Ctrl+C stops them
```

You can also start each service in its own terminal: `python user_service\app.py`,
`python audit_service\app.py`, `python notification_service\app.py`.

Check they are up: open http://127.0.0.1:5001/health, :5005/health, :5008/health.

### Sample accounts (from `database/seed.py`)

| Username | Password | Role |
|---|---|---|
| admin | Admin@12345 | Security Administrator |
| analyst | Analyst@12345 | Security Analyst |
| employee | Employee@12345 | Regular Employee |
| employee2 | Employee2@12345 | Regular Employee |
| auditor | Auditor@12345 | Auditor |
| suspended | Suspended@12345 | Regular Employee, **Suspended** (login is refused) |

---

## 2. Test it

### Postman (for the report screenshots)
1. Postman → **Import** → `postman/Sprint1_Users_Audit_Notifications.postman_collection.json`
2. Click the collection → **Variables** → set `student_name` to your full name, and `service_key`
   to the `SERVICE_API_KEY` value from your `.env`. Save.
3. Run folder **0. Authentication** first (logins store each role's token automatically).
4. Then run the other folders in order, or click **Run collection** to run all 101 requests
   (each one has tests that check the expected status code).

The collection covers every API with success cases, validation errors (400), missing/invalid
token (401), wrong role (403), not found (404) and duplicates (409).

### Automated tests
With the services running:
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
sprint1/
├── shared/                     code used by all services
│   ├── config.py               settings + secrets from .env
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
├── audit_service/              Service 5
├── notification_service/       Service 8
├── database/schema.sql         all 10 tables of the system + immutability trigger
├── database/init_db.py, seed.py
├── postman/                    collection (+ build_collection.py that generates it)
├── tests/test_e2e.py
├── docs/API_DOCUMENTATION.md
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
| POST /users/register | ✔ any role | ✘ | ✔ (Regular only, also anonymous) | ✘ |
| PUT /users/{id} | ✔ (+ role, status) | ✘ | own only | ✘ |
| DELETE /users/{id} | ✔ | ✘ | ✘ | ✘ |
| GET /users | ✔ | ✘ | ✘ | ✔ |
| GET /users/{username} | ✔ | ✘ | own only | ✔ |
| POST /logs | ✔ | ✘ | ✘ | ✘ |
| GET /logs | ✔ | ✘ | ✘ | ✔ |
| GET /logs/{id}, /logs/search | ✔ | ✔ | ✘ | ✔ |
| DELETE /logs/{id} | ✔ | ✘ | ✘ | ✘ |
| GET /logs/user/{id} | ✔ | ✘ | ✘ | ✔ |
| POST /notifications | ✔ | ✘ | ✘ | ✘ |
| GET /notifications/user/{id}, /{id} | ✔ | own | own | ✔ |
| PUT /notifications/{id}/read | ✔ | own | own | ✘ (read-only) |
| GET /notifications/search | ✔ | own | ✘ | ✔ |
| DELETE /notifications/{id} | ✔ | ✘ | ✘ | ✘ |

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
* Service-to-service calls carry `X-Service-Key` (compared in constant time). `/internal/*` endpoints
  refuse anything else. If a service is down, the caller keeps working and writes the event to its
  local log file.

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
`NOTIFICATION_DELETED`, `LOG_DELETED`.

### For teammates
* All 10 tables are in `database/schema.sql` (one shared database with real foreign keys).
* To log from your service: `from shared.audit_client import log_event`
* To notify (incident assignment, threat/vulnerability alerts): `from shared.notification_client import notify`
* To protect a route: add your permissions to `shared/permissions.py` and use `@require_permission(...)`.

---

## 5. GitHub
`.gitignore` excludes `.env`, the database, logs, backups and certificates — secrets never reach GitHub.
Suggested commits: "Added shared security and auth layer", "Implemented user registration and login
API", "Implemented audit logging service", "Implemented notification service", "Added Postman collection".
