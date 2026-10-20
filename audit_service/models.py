from shared.security import crypto


class AuditLog:
    # builds an AuditLog from a row and decrypts the description
    def __init__(self, row):
        self.log_id = row["log_id"]
        self.user_id = row["user_id"]
        self.original_user_id = row["original_user_id"]
        self.actor_username = row["actor_username"]
        self.action = row["action"]
        self.description = crypto.decrypt(row["description"])
        self.timestamp = row["timestamp"]
        self.severity = row["severity"]
        self.related_service = row["related_service"]
        self.integrity_hash = row["integrity_hash"]

    # puts the log values in a fixed order so the signature is always computed the same way
    @staticmethod
    def signature_parts(original_user_id, actor_username, action, description, timestamp,
                        severity, related_service):
        return (original_user_id, actor_username, action, description, timestamp, severity,
                related_service)

    # recomputes the signature to see if the log was changed
    @property
    def integrity_ok(self):
        return crypto.verify_signature(self.integrity_hash, *self.signature_parts(
            self.original_user_id, self.actor_username, self.action, self.description,
            self.timestamp, self.severity, self.related_service))

    # the log as json, with integrity showing verified or TAMPERED
    def to_dict(self):
        return {
            "log_id": self.log_id,
            "user_id": self.original_user_id,
            "username": self.actor_username,
            "user_still_exists": self.user_id is not None,
            "action": self.action,
            "description": self.description,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "related_service": self.related_service,
            "integrity": "verified" if self.integrity_ok else "TAMPERED",
        }
