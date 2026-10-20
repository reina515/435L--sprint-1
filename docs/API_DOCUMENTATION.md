# API Documentation – Users (5001), Security Audit Logging (5005), Notifications (5008)

**Student:** `<Your Full Name>` (every response also carries the header `X-Student-Name`)

## Conventions

* Base URLs: `http://127.0.0.1:5001`, `http://127.0.0.1:5005`, `http://127.0.0.1:5008`
* **Every route starts with the student's full name: `/Reina_Hani`.** The paths below are written
  without it for readability, e.g. `POST /users/login` is called as
  `http://127.0.0.1:5001/Reina_Hani/users/login`.
* Body format: JSON, header `Content-Type: application/json` (otherwise **415**). Max body size 16 KB (**413**).
* Protected APIs need `Authorization: Bearer <token>` (token from `POST /users/login`).
* Internal service calls use `X-Service-Key: <SERVICE_API_KEY>` instead of a token.
* Enumerated values are case-insensitive on input (`"high"` → `"High"`).
* List endpoints accept `?limit=` (1–500, default 100) and `?offset=` (default 0).

**Success format**
```json
{ "status": "success", "message": "...", "data": { ... } }
```
**Error format**
```json
{ "status": "error", "message": "User does not have permission to perform this operation" }
```

| Code | Meaning |
|---|---|
| 400 | Validation error (missing field, bad format, invalid value, unexpected field, empty/invalid JSON) |
| 401 | Not authenticated (no token, malformed/invalid/expired/revoked token, wrong credentials) |
| 403 | Authenticated but not allowed (role / ownership), or account inactive/suspended |
| 404 | Resource not found |
| 405 | HTTP method not allowed |
| 409 | Duplicate (username or email already used) |
| 413 / 415 | Body too large / not JSON |
| 500 | Internal error (generic message, details only in the server log) |
| 503 | A required service is unreachable |

---

# Service 1 – Users and Identity Management (port 5001)

## 1. User Registration
**POST** `/users/register` — creates an account.
Auth: none (self-registration as *Regular Employee*), or Admin token (any role, may set `account_status`).
Analyst / Auditor tokens → 403.

Request body (all required unless noted):
```json
{
  "full_name": "Maya Haddad",
  "username": "maya",
  "email": "maya@company.com",
  "password": "Secure#Pass2026",
  "department": "Finance",
  "role": "Regular Employee",
  "account_status": "Active"
}
```
`account_status` optional, admin only. Roles: `Security Administrator`, `Security Analyst`,
`Regular Employee`, `Auditor`.

Validation: required fields; full name 2–100 letters; username 3–30 `[A-Za-z0-9_.-]`; valid email;
password ≥ 8 chars, ≤ 72 bytes, upper + lower + digit + special, must not contain the username;
department 2–100 chars; no `<` `>` or control characters; no unknown fields.

Response **201**
```json
{ "status": "success", "message": "User registered successfully",
  "data": { "user_id": 7, "full_name": "Maya Haddad", "username": "maya", "email": "maya@company.com",
            "department": "Finance", "role": "Regular Employee", "account_status": "Active",
            "created_at": "2026-10-17 12:52:42", "updated_at": null, "last_login": null,
            "failed_login_attempts": 0 } }
```
Errors: 400 validation (e.g. `{"message":"Password does not meet requirements","details":{"password_requirements":["an uppercase letter","a digit"]}}`),
403 non-admin requesting a privileged role, 409 `Username 'maya' is already taken` / `An account with this email already exists`.

**Duplicate usernames:** checked with a case-insensitive lookup before inserting (`Maya` = `maya`), and
enforced by the `UNIQUE COLLATE NOCASE` constraint; a race between two requests hits the constraint and
also returns 409. Emails are checked through their HMAC blind index (unique column).

Side effects: `USER_CREATED` log (+ `ROLE_ASSIGNED` for privileged roles), welcome notification.

## 2. User Login
**POST** `/users/login` — Auth: none.
```json
{ "username": "admin", "password": "Admin@12345" }      // or { "email": "admin@security.local", ... }
```
Response **200**
```json
{ "status": "success", "message": "Authentication successful",
  "data": { "token": "eyJhbGciOi...", "token_type": "Bearer", "expires_at": "2026-10-17 13:57:53",
            "user": { "user_id": 1, "username": "admin", "role": "Security Administrator", ... } } }
```
Errors: 400 missing fields; 401 `Invalid username/email or password`; 403 `Account is suspended. Contact a security administrator.`
Logs: `LOGIN_SUCCESS`, `LOGIN_FAILED`, `LOGIN_BLOCKED`, `BRUTE_FORCE_SUSPECTED` (5 consecutive failures, Critical).

## Logout
**POST** `/users/logout` — Auth: any role. Revokes the current token (stored in `revoked_tokens`).
Response 200 `Logged out successfully, the token can no longer be used`. Using it afterwards → 401.

## 3. Update User Information
**PUT** `/users/{id}` — Auth: Admin (any user), Regular Employee (own id only).
```json
{ "full_name": "Maya Haddad-Khoury", "email": "maya.k@company.com", "department": "Risk" }
```
Admin may also send `"role"` and `"account_status"` (`Active`/`Inactive`/`Suspended`).
Response **200** `User updated successfully` + updated user. If nothing changed: 200 `No changes were needed...`.
Errors: 400 invalid id/field, admin changing own role/status; 403 other user's id or non-admin changing role;
404 `User with id 99 not found`; 409 email already used.
Logs: `USER_UPDATED`, `ROLE_CHANGED`, `ACCOUNT_STATUS_CHANGED`; the user is notified of role/status changes.

## 4. Delete User
**DELETE** `/users/{id}` — Auth: Admin only.
Response **200** `{"status":"success","message":"User deleted successfully","data":{"user_id":7,"username":"maya"}}`
Errors: 400 deleting yourself / invalid id; 403 non-admin (logged as `UNAUTHORIZED_ACCESS`); 404 not found.
**How permissions are checked:** `@require_permission("users:delete")` verifies the JWT, reloads the user
from the DB, and looks up the role in `shared/permissions.py`; only `Security Administrator` is listed.

## 5. Retrieve All Users
**GET** `/users?limit=100&offset=0` — Auth: Admin, Auditor.
Response **200**: `data` is an array of user objects (no password or hashes), plus `count` (returned now),
`total` (all users), `limit`, `offset`.

## 6. Retrieve User By Username
**GET** `/users/{username}` — Auth: Admin, Auditor (any), Regular Employee (own username only).
200 user object; 403 another user's profile (employee) or Analyst; 404 `User 'nobody' not found`; 400 invalid username format.

## View roles and permissions
**GET** `/roles` — Auth: Admin, Auditor. Returns roles, account statuses, password policy and the full RBAC matrix.

## Internal (service-to-service, header `X-Service-Key`)
* **GET** `/internal/users/{id}` → `{user_id, username, full_name, role, account_status}` or 404
* **GET** `/internal/users?role=Security Administrator&status=Active` → list
Without a valid key → 403.

---

# Service 5 – Security Audit Logging (port 5005)

Log object:
```json
{ "log_id": 307, "user_id": 1, "username": "admin", "user_still_exists": true,
  "action": "LOGIN_SUCCESS", "description": "User 'admin' logged in from 127.0.0.1",
  "timestamp": "2026-10-17 12:57:53", "severity": "Information", "related_service": "Users",
  "integrity": "verified" }
```
Severities: `Information`, `Warning`, `Error`, `Critical`.
Related services: `Users`, `Assets`, `Incidents`, `Threat Intelligence`, `Audit Logging`, `Reports`,
`Vulnerabilities`, `Notifications`, `Playbooks`.
Timestamps are UTC. `integrity` is `TAMPERED` if the row was altered outside the API.

## 1. Create Log Record
**POST** `/logs` — Auth: Admin token, or `X-Service-Key` (used automatically by all services).
```json
{ "user_id": 2, "action": "INCIDENT_CREATED", "description": "Analyst opened incident #12",
  "severity": "Information", "related_service": "Incidents" }
```
`action` is normalised to UPPER_SNAKE_CASE (`"incident created"` → `INCIDENT_CREATED`), 3–50 chars.
Description 3–1000 chars. `user_id` must exist (admin); services may send `null` for system events.
Response **201** `Log record created successfully` + log. A **Critical** log also sends a Security Alert
notification to every active administrator.
Errors: 400 missing/invalid field or unknown user; 401; 403 (Auditor, Analyst, Employee).

## 2. Retrieve All Logs
**GET** `/logs?limit=100&offset=0` — Auth: Admin, Auditor. Newest first. `count`, `total`, `limit`, `offset`.
Analyst/Employee → 403.

## 3. Retrieve Specific Log
**GET** `/logs/{id}` — Auth: Admin, Auditor, Analyst. 404 `Log with id 999 not found`, 400 non-numeric id.

## 4. Search Logs
**GET** `/logs/search` — Auth: Admin, Auditor, Analyst. At least one criterion required (else 400).

| Parameter | Filter |
|---|---|
| `user` / `user_id` | numeric → user id; text → username |
| `action` | contains (e.g. `LOGIN` matches LOGIN_SUCCESS and LOGIN_FAILED) |
| `severity` | exact |
| `service` / `related_service` | exact |
| `date` | exact day `YYYY-MM-DD` |
| `date_from`, `date_to` | inclusive range |

Criteria are combined with AND. Unknown parameters → 400. Response includes `filters`, `count`, `total`.
No match → 200 with `"message": "No logs match the search criteria"` and an empty list.
Example: `/logs/search?user=employee&severity=Warning&date_from=2026-10-01`

## 5. Delete Logs
**DELETE** `/logs/{id}` — Auth: Admin only. 200 `Log deleted successfully`; 403 others; 404 not found.
The deletion is itself logged (`LOG_DELETED`, Warning).

## 6. Retrieve Logs By User
**GET** `/logs/user/{user_id}` — Auth: Admin, Auditor.
Filters on `original_user_id`, so the history of a deleted user is still available (`user_exists: false`).
No logs → 200, `"message": "No logs found for user 987654"`, `count: 0`.

---

# Service 8 – Notification and Alert Management (port 5008)

Notification object:
```json
{ "notification_id": 44, "user_id": 2, "title": "Malicious IP observed",
  "message": "185.220.101.4 matched a threat indicator.", "notification_type": "Threat Alert",
  "severity": "Critical", "status": "Unread", "created_at": "2026-10-17 12:57:03", "read_at": null }
```
Types: `Incident Assignment`, `Security Alert`, `System Notification`, `Threat Alert`, `Vulnerability Alert`.
Severities: `Low`, `Medium`, `High`, `Critical`. Status: `Unread`, `Read`.

## 1. Create Notification
**POST** `/notifications` — Auth: Admin token or `X-Service-Key` (other services).
```json
{ "user_id": 2, "title": "New incident assigned", "message": "Incident #12 has been assigned to you.",
  "notification_type": "Incident Assignment", "severity": "High" }
```
The recipient is verified by calling the Users service (`GET /internal/users/{id}`).
Response **201**. Errors: 400 validation; 403 non-admin; 404 `User with id 999999 not found`; 503 Users service down.

Generated automatically: welcome (registration), role change, account status change, brute-force
Security Alert, Critical audit events (to all admins). Teammates' services call `notify(...)` for incident
assignment, threat alerts and vulnerability alerts.

## 2. Retrieve User Notifications
**GET** `/notifications/user/{user_id}?status=Unread` — Auth: Admin, Auditor (any user); Analyst,
Employee (own id only, otherwise 403). Response includes `count`, `total`, `unread`.
User with no notifications → 200, `"message": "User 5 has no notifications"`, empty list. Unknown user → 404.

## 3. Retrieve Specific Notification
**GET** `/notifications/{id}` — Admin, Auditor: any; Analyst, Employee: only their own (403 otherwise). 404 not found.

## 4. Mark Notification as Read
**PUT** `/notifications/{id}/read` — no body. Admin: any; Analyst, Employee: own only. Auditor → 403 (read-only role).
Unread → `status: "Read"`, `read_at` set, `previous_status: "Unread"`.
Already read → 200 `Notification was already marked as read`, original `read_at` kept.

## 5. Search Notifications
**GET** `/notifications/search?user_id=&type=&severity=&status=` — Admin, Auditor: all notifications;
Analyst: automatically limited to own (asking for another user → 403); Employee → 403.
`type` = `notification_type`, `user` = `user_id`. Invalid values / unknown parameters → 400.

## 6. Delete Notification
**DELETE** `/notifications/{id}` — Admin only. 200 / 403 / 404. Logged as `NOTIFICATION_DELETED`.
