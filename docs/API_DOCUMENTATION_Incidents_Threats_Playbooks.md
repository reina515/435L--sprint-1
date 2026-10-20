# API Documentation – Incidents (5003), Threat Intelligence (5004), Playbooks (5009)

**Student:** Hayam Itani (every route is under `/hayam-itani`, and every response also carries the header `X-Student-Name`)

## Conventions

* Base URLs: `http://127.0.0.1:5003/hayam-itani`, `http://127.0.0.1:5004/hayam-itani`, `http://127.0.0.1:5009/hayam-itani`
* Same conventions as the Users / Audit / Notifications documentation: JSON bodies with
  `Content-Type: application/json` (otherwise **415**), max body 16 KB (**413**), `Authorization: Bearer <token>`
  from `POST /users/login`, case-insensitive enumerated values (`"high"` → `"High"`), and
  `?limit=` (1–500, default 100) / `?offset=` on list endpoints.
* Success format `{ "status": "success", "message": "...", "data": ... }`,
  error format `{ "status": "error", "message": "..." }`.
* Every rejected permission check returns **403** `User does not have permission to perform this operation`
  and is written to the audit log as `UNAUTHORIZED_ACCESS`; a missing/invalid/expired token returns **401**
  and is logged as `UNAUTHENTICATED_ACCESS`.
* Severities: `Low`, `Medium`, `High`, `Critical`.
  Incident categories: `Malware`, `Phishing`, `Unauthorized Access`, `Data Leakage`, `Denial of Service`,
  `Account Compromise`, `Other`.

| Code | Meaning |
|---|---|
| 400 | Validation error (missing field, bad format, invalid value, unexpected field, empty body, broken workflow rule) |
| 401 | Not authenticated (no token, malformed/invalid/expired/revoked token) |
| 403 | Authenticated but not allowed (role, or not the caller's own record) |
| 404 | Resource not found (incident, asset, user, threat, playbook, action) |
| 409 | Conflict (duplicate threat or step number, closed incident, completed action, concurrent change) |
| 503 | The Users service is unreachable (needed to check analysts / assigned users) |

---

# Service 3 – Incident Management (port 5003)

Incident object:
```json
{ "incident_id": 4, "title": "Customer data exposed",
  "description": "Customer table exported to an unknown external address", "category": "Data Leakage",
  "severity": "Critical", "reporter_id": 1, "asset_id": 3, "assigned_analyst_id": 2,
  "status": "Under Investigation", "next_allowed_status": "Mitigated",
  "created_at": "2026-10-19 12:11:28", "resolved_at": null,
  "notes": [ { "note_id": 1, "incident_id": 4, "analyst_id": 2,
               "content": "Checked VPN logs: 3 logins from 203.0.113.7 at night",
               "created_at": "2026-10-19 12:37:39" } ] }
```
Lifecycle: `Open` → `Under Investigation` → `Mitigated` → `Resolved` → `Closed`, one step at a time.
`resolved_at` is set when the incident becomes Resolved. Only an administrator closes an incident (D2).

## 1. Create Incident
**POST** `/incidents` — reports a cybersecurity incident; the reporter is the logged-in user.
Auth: Admin, Regular Employee. Analyst / Auditor → 403.

Request body (all required):
```json
{ "title": "Customer data exposed",
  "description": "Customer table exported to an unknown external address",
  "category": "Data Leakage", "severity": "Critical", "asset_id": 3 }
```
Validation: title 3–150 chars; description 5–2000 chars; category and severity from the lists above;
`asset_id` a positive integer of an existing asset; no `<` `>` or control characters; no unknown fields.

Response **201** `Incident created successfully` + the incident (status `Open`, no notes).
Errors: 400 `Missing required field(s): description, category, severity, asset_id`,
400 `Invalid severity. Allowed values: Low, Medium, High, Critical`; 401; 403;
404 `Asset with id 99999 not found`.
Side effects: `INCIDENT_CREATED` log; a **Critical** incident sends a Security Alert notification to every
active administrator.

## 2. Retrieve All Incidents
**GET** `/incidents?status=&severity=&limit=&offset=` — all incidents with status and assigned analyst, newest first.
Auth: Admin, Auditor (all incidents); Analyst (only incidents assigned to them); Regular Employee (only
incidents they reported) – decision D1.
Response **200**: `data` (incidents without notes), `count`, `total`, `filters`.
No match → 200 `No incidents match the criteria` with an empty list.
Errors: 400 `Unknown query parameter(s): colour`, 400 invalid status/severity filter; 401.

## 3. Retrieve Specific Incident
**GET** `/incidents/{id}` — complete incident including its investigation notes (oldest first).
Auth: Admin, Auditor (any); Analyst (assigned to them); Regular Employee (reported by them).
Response **200** `Incident retrieved successfully` + incident.
Errors: 400 `'id' must be a positive integer`; 401; 403 another person's incident;
404 `Incident with id 99999 not found`.

## 4. Assign Incident to Analyst
**PUT** `/incidents/{id}/assign` — Auth: Admin only.
```json
{ "analyst_id": 2 }
```
Rules: the incident exists and is not closed; the user exists (checked through the Users service,
`GET /internal/users/{id}`), has the **Security Analyst** role and is Active.
Response **200** `Incident assigned successfully` + incident with `assigned_analyst_id`.
Errors: 400 `User 'employee' is not a Security Analyst (role: Regular Employee)`; 401; 403 non-admin;
404 incident or user not found; 409 incident closed; 503 Users service unavailable.
Side effects: `INCIDENT_ASSIGNED` log; the analyst receives an **Incident Assignment** notification
(`Incident #4 assigned to you`).

## 5. Update Incident Status
**PUT** `/incidents/{id}/status` — Auth: Admin; Analyst (only incidents assigned to them).
```json
{ "status": "Under Investigation" }
```
Response **200** `Incident status updated from Open to Under Investigation` + incident, plus
`previous_status` and `new_status`.
Errors: 400 `Invalid status transition from Open to Closed. Next allowed status: Under Investigation`
(also logged as `INVALID_STATUS_TRANSITION`, Warning); 400 unknown status value; 400
`Assign the incident to a Security Analyst before starting the investigation`; 401;
403 not assigned to the analyst, or an analyst trying to close (D2); 404; 409 changed by another request.
Side effects: `INCIDENT_STATUS_CHANGED` log.

## 6. Add Investigation Notes
**POST** `/incidents/{id}/notes` — Auth: Admin; Analyst (only incidents assigned to them).
```json
{ "content": "Checked VPN logs: 3 logins from 203.0.113.7 at night" }
```
Content 1–2000 chars (multi-line allowed).
Response **201** `Investigation note added successfully` with `data.note` (the new note) and
`data.incident` (the incident with all its notes). Each note is linked to one incident by the foreign
key `investigation_notes.incident_id`.
Errors: 400 `Missing required field(s): content`; 401; 403; 404;
409 `Incident #4 is closed; notes can no longer be added`.
Side effects: `INCIDENT_NOTE_ADDED` log.

---

# Service 4 – Threat Intelligence (port 5004)

Threat object:
```json
{ "threat_id": 1, "threat_type": "IP Address", "threat_value": "203.0.113.45",
  "description": "Command-and-control server seen in VPN logs", "severity": "High",
  "source": "Internal SOC", "date_added": "2026-10-19 13:03:44" }
```
Types and accepted value formats:

| Type | Format |
|---|---|
| `IP Address` | valid IPv4 or IPv6 (`999.10.10.1` → 400) |
| `Domain` | letters/digits/hyphens labels, at least one dot, letters-only TLD, stored in lower case |
| `File Hash` | hexadecimal, 32 (MD5), 40 (SHA-1) or 64 (SHA-256) characters, stored in lower case |
| `Malware Signature`, `Other` | free text, 2–255 chars |

The same type + value cannot be stored twice (checked first, and enforced by `UNIQUE (threat_type, threat_value)`).
Values are normalised before the check, so `LOGIN-UPDATE.EXAMPLE` is a duplicate of `login-update.example`.

## 1. Add Threat Indicator
**POST** `/threats` — Auth: Admin only.
```json
{ "threat_type": "IP Address", "threat_value": "203.0.113.45",
  "description": "Command-and-control server seen in VPN logs", "severity": "High", "source": "Internal SOC" }
```
All fields required; description 3–1000 chars; source 2–100 chars.
Response **201** `Threat indicator added successfully` + threat.
Errors: 400 `Invalid IP address: '999.10.10.1'`, `Invalid domain: 'not a domain'`, `Invalid file hash: ...`,
`Invalid threat_type. Allowed values: ...`, `Request body cannot be empty`; 401; 403 Analyst/Auditor/Employee;
409 `IP Address '203.0.113.45' already exists (threat id 1)`.
Side effects: `THREAT_CREATED` log; a **High** or **Critical** indicator sends a **Threat Alert**
notification to every active analyst.

## 2. Retrieve All Threat Indicators
**GET** `/threats?limit=&offset=` — Auth: Admin, Analyst, Auditor. Employee → 403.
Response **200**: `data` (type, value, description, severity, source, date added), `count`, `total`, newest first.

## 3. Retrieve Specific Threat Indicator
**GET** `/threats/{id}` — Auth: Admin, Analyst, Auditor.
200 threat; 400 non-numeric id; 404 `Threat indicator with id 99999 not found`.

## 4. Search Threat Indicators
**GET** `/threats/search` — Auth: Admin, Analyst, Auditor (D3). Employee → 403.
At least one criterion is required (else 400). Criteria are combined with AND.

| Parameter | Filter |
|---|---|
| `type` | exact threat type |
| `value` | part of the value (contains) |
| `severity` | exact |
| `source` | part of the source (contains) |

Response **200** with `data`, `count`, `total`, `filters`. No match → 200
`No threat indicators match the search criteria` and an empty list.
Example: `/threats/search?type=Domain&severity=Critical`.
Errors: 400 `Unknown search parameter(s): colour`, 400 no criterion, 400 invalid type/severity; 401; 403.
Security: values go into the SQL only as parameters (`LIKE ? ESCAPE '\'`, with `%` and `_` escaped), so
`?value=' OR '1'='1` is treated as plain text and matches nothing.

## 5. Update Threat Information
**PUT** `/threats/{id}` — Auth: Admin only. Updatable: `description`, `severity`, `source` (at least one).
```json
{ "severity": "Critical", "description": "Confirmed by a second source" }
```
Response **200** `Threat indicator updated successfully` + updated threat, plus `previous` with the old
values of the changed fields. Same values again → 200 `No changes: the values sent are the same as the stored ones`.
Errors: 400 `threat_type and threat_value cannot be changed: they identify the indicator. Delete it and add a
new one instead`; 400 invalid severity / empty body / unknown field; 401; 403; 404.
Side effects: `THREAT_UPDATED` log listing each change (e.g. `severity 'Medium' to 'Critical'`).

## 6. Delete Threat Indicator
**DELETE** `/threats/{id}` — Auth: Admin only.
Response **200** `Threat indicator deleted successfully` with `threat_id`, `threat_type`, `threat_value`.
Errors: 401; 403 (Analyst, logged as `UNAUTHORIZED_ACCESS`); 404.
Side effects: `THREAT_DELETED` log (Warning).

---

# Service 9 – Security Playbook and Response Automation (port 5009)

Playbook object (with its ordered response actions):
```json
{ "playbook_id": 1, "name": "Phishing response", "description": "Steps when a phishing email is reported",
  "incident_category": "Phishing", "severity": "High", "created_by": 1, "created_at": "2026-10-19 13:28:40",
  "action_count": 2, "progress": { "completed": 1, "total": 2 },
  "actions": [
    { "action_id": 1, "playbook_id": 1, "description": "Isolate the affected mailbox", "step_number": 1,
      "status": "Completed", "assigned_user_id": null, "completed_at": "2026-10-19 13:53:18" },
    { "action_id": 2, "playbook_id": 1, "description": "Block the sender domain", "step_number": 2,
      "status": "In Progress", "assigned_user_id": 2, "completed_at": null } ] }
```
Action status: `Pending` → `In Progress` → `Completed`, one step at a time; Completed is final.
A step cannot start while an earlier step of the same playbook is unfinished (D4).
Step numbers are unique within a playbook (`UNIQUE (playbook_id, step_number)`).

## 1. Create Response Playbook
**POST** `/playbooks` — Auth: Admin only. `created_by` is the logged-in administrator.
```json
{ "name": "Phishing response", "description": "Steps when a phishing email is reported",
  "incident_category": "Phishing", "severity": "High" }
```
All fields required; name 3–150 chars; description 3–1000 chars.
Response **201** `Playbook created successfully` + playbook (no actions yet).
Errors: 400 `Missing required field(s): name`, invalid severity, `Invalid incident_category. Allowed values: ...`;
401; 403 non-admin. Side effects: `PLAYBOOK_CREATED` log.

## 2. Retrieve All Playbooks
**GET** `/playbooks?incident_category=&severity=&limit=&offset=` — Auth: Admin, Analyst, Auditor. Employee → 403.
Response **200**: `data` (playbooks with `action_count` and `progress`, without the action list), `count`,
`total`, `filters`. Errors: 400 unknown parameter / invalid filter; 401; 403.

## 3. Retrieve Specific Playbook
**GET** `/playbooks/{id}` — Auth: Admin, Analyst, Auditor.
200 playbook with its actions in step order; 400 non-numeric id; 404 `Playbook with id 99999 not found`.

## 4. Add Response Action
**POST** `/playbooks/{id}/actions` — Auth: Admin, Analyst.
```json
{ "description": "Block the sender domain", "step_number": 2, "assigned_user_id": 2 }
```
`description` (3–500 chars) and `step_number` (positive integer) required; `assigned_user_id` optional,
checked through the Users service (must exist and be Active).
Response **201** `Response action added successfully` with `data.action` (status `Pending`) and
`data.playbook` (all steps in order).
Errors: 400 `'step_number' must be a positive integer`; 401; 403 Auditor/Employee;
404 playbook or user not found; 409 `Step 2 already exists in playbook #1`; 503 Users service unavailable.
Side effects: `RESPONSE_ACTION_ADDED` log; the assigned user receives a System Notification.

## 5. Update Response Action Status
**PUT** `/actions/{id}/status` — Auth: Admin, Analyst. At least one of:
```json
{ "status": "Completed", "assigned_user_id": 2, "completion_date": "2026-10-19" }
```
`completed_at` is set automatically when the status becomes Completed (or taken from `completion_date`,
which may not be in the future or before the playbook was created).
Response **200** `Response action updated successfully` + action, plus `previous_status`.
Errors: 400 `Invalid status transition from Pending to Completed. Next allowed status: In Progress`;
400 `Complete step(s) 1 of this playbook first`; 400 `completion_date can only be set when the status
becomes Completed`; 400 invalid status; 401; 403 Employee/Auditor; 404 action or user not found;
409 `Action #1 is completed; completed actions cannot change`.
Side effects: `RESPONSE_ACTION_UPDATED` log for every change (old and new status), which keeps the
execution history of each action; a newly assigned user is notified.

## 6. Delete Playbook
**DELETE** `/playbooks/{id}` — Auth: Admin only.
Response **200** `Playbook deleted successfully` with `playbook_id` and `actions_deleted`
(its response actions are deleted with it: `ON DELETE CASCADE`).
Errors: 401; 403 (Analyst, logged as `UNAUTHORIZED_ACCESS`); 404 `Playbook with id 3 not found`.
Side effects: `PLAYBOOK_DELETED` log (Warning).
