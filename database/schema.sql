PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    user_id               INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name             TEXT    NOT NULL,
    username              TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email_encrypted       TEXT    NOT NULL,
    email_hash            TEXT    NOT NULL UNIQUE,
    password_hash         TEXT    NOT NULL,
    department            TEXT    NOT NULL,
    role                  TEXT    NOT NULL DEFAULT 'Regular Employee'
                          CHECK (role IN ('Security Administrator', 'Security Analyst',
                                          'Regular Employee', 'Auditor')),
    account_status        TEXT    NOT NULL DEFAULT 'Active'
                          CHECK (account_status IN ('Active', 'Inactive', 'Suspended')),
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    updated_at            TEXT,
    last_login            TEXT
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT PRIMARY KEY,
    user_id    INTEGER,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_name        TEXT NOT NULL,
    asset_type        TEXT NOT NULL,
    ip_address        TEXT NOT NULL,
    operating_system  TEXT,
    owner_id          INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    department        TEXT NOT NULL,
    location          TEXT,
    criticality_level TEXT NOT NULL CHECK (criticality_level IN ('Low', 'Medium', 'High', 'Critical')),
    status            TEXT NOT NULL DEFAULT 'Active'
                      CHECK (status IN ('Active', 'Inactive', 'Under Maintenance')),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title               TEXT NOT NULL,
    description         TEXT NOT NULL,
    category            TEXT NOT NULL,
    severity            TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    reporter_id         INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    asset_id            INTEGER REFERENCES assets(asset_id) ON DELETE SET NULL,
    assigned_analyst_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    status              TEXT NOT NULL DEFAULT 'Open'
                        CHECK (status IN ('Open', 'Under Investigation', 'Mitigated', 'Resolved', 'Closed')),
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    resolved_at         TEXT
);

CREATE TABLE IF NOT EXISTS investigation_notes (
    note_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    analyst_id  INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    content     TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE TABLE IF NOT EXISTS threats (
    threat_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type  TEXT NOT NULL CHECK (threat_type IN ('IP Address', 'Domain', 'File Hash',
                                                      'Malware Signature', 'Other')),
    threat_value TEXT NOT NULL,
    description  TEXT,
    severity     TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    source       TEXT NOT NULL,
    date_added   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    UNIQUE (threat_type, threat_value)
);

CREATE TABLE IF NOT EXISTS logs (
    log_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    original_user_id INTEGER,
    actor_username   TEXT,
    action           TEXT NOT NULL,
    description      TEXT NOT NULL,
    timestamp        TEXT NOT NULL,
    severity         TEXT NOT NULL CHECK (severity IN ('Information', 'Warning', 'Error', 'Critical')),
    related_service  TEXT NOT NULL,
    integrity_hash   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_logs_original_user ON logs(original_user_id);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp     ON logs(timestamp);

CREATE TRIGGER IF NOT EXISTS logs_are_immutable
BEFORE UPDATE ON logs
WHEN NOT (
        NEW.user_id IS NULL AND OLD.user_id IS NOT NULL
    AND NEW.log_id           IS OLD.log_id
    AND NEW.original_user_id IS OLD.original_user_id
    AND NEW.actor_username   IS OLD.actor_username
    AND NEW.action           IS OLD.action
    AND NEW.description      IS OLD.description
    AND NEW.timestamp        IS OLD.timestamp
    AND NEW.severity         IS OLD.severity
    AND NEW.related_service  IS OLD.related_service
    AND NEW.integrity_hash   IS OLD.integrity_hash
)
BEGIN
    SELECT RAISE(ABORT, 'Audit logs are immutable and cannot be modified');
END;

CREATE TABLE IF NOT EXISTS vulnerabilities (
    vulnerability_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    title             TEXT NOT NULL,
    description       TEXT,
    cve_id            TEXT,
    cvss_score        REAL CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
    severity          TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    asset_id          INTEGER NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    discovery_source  TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'Open'
                      CHECK (status IN ('Open', 'Under Investigation', 'In Progress', 'Resolved', 'Closed')),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    resolved_at       TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    notification_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    title             TEXT NOT NULL,
    message           TEXT NOT NULL,
    notification_type TEXT NOT NULL CHECK (notification_type IN ('Incident Assignment', 'Security Alert',
                                                                  'System Notification', 'Threat Alert',
                                                                  'Vulnerability Alert')),
    severity          TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    status            TEXT NOT NULL DEFAULT 'Unread' CHECK (status IN ('Unread', 'Read')),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    read_at           TEXT
);

CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);

CREATE TABLE IF NOT EXISTS playbooks (
    playbook_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL,
    description       TEXT,
    incident_category TEXT NOT NULL,
    severity          TEXT NOT NULL CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    created_by        INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now'))
);

CREATE TABLE IF NOT EXISTS response_actions (
    action_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    playbook_id      INTEGER NOT NULL REFERENCES playbooks(playbook_id) ON DELETE CASCADE,
    description      TEXT NOT NULL,
    step_number      INTEGER NOT NULL CHECK (step_number > 0),
    status           TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'In Progress', 'Completed')),
    assigned_user_id INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    completed_at     TEXT,
    UNIQUE (playbook_id, step_number)
);
