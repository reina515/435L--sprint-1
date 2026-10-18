"""
Incident domain models (Incident Management Service).
Implemented by: Hayam Itani

each class wraps one table row, keeps its own rules (encapsulation:
the lifecycle lives in Incident, never in the routes) and exposes to_dict().
"""


class InvestigationNote:
    """One row of the ``investigation_notes`` table.

    :param row: a row from ``SELECT * FROM investigation_notes``
    :type row: sqlite3.Row
    """

    def __init__(self, row):
        self.note_id = row["note_id"]
        self.incident_id = row["incident_id"]
        self.analyst_id = row["analyst_id"]
        self.content = row["content"]
        self.created_at = row["created_at"]

    def to_dict(self):
        """Return the note as a JSON-ready dict.

        :return: the 5 attributes above
        :rtype: dict
        """
        return {
            "note_id": self.note_id,
            "incident_id": self.incident_id,
            "analyst_id": self.analyst_id,
            "content": self.content,
            "created_at": self.created_at,
        }


class Incident:
    """One row of the ``incidents`` table plus its investigation notes.

    :param row: a row from ``SELECT * FROM incidents``
    :type row: sqlite3.Row
    :param notes: the incident's notes, oldest first, defaults to None
    :type notes: list[InvestigationNote], optional
    """

    STATUSES = ("Open", "Under Investigation", "Mitigated", "Resolved", "Closed")

    NEXT_STATUS = {
        "Open": "Under Investigation",
        "Under Investigation": "Mitigated",
        "Mitigated": "Resolved",
        "Resolved": "Closed",
    }
   
    def __init__(self, row, notes=None):
        self.incident_id = row["incident_id"]
        self.title = row["title"]
        self.description = row["description"]
        self.category = row["category"]
        self.severity = row["severity"]
        self.reporter_id = row["reporter_id"]
        self.asset_id = row["asset_id"]
        self.status = row["status"]
        self.assigned_analyst_id = row["assigned_analyst_id"]
        self.created_at = row["created_at"]
        self.resolved_at = row["resolved_at"]
        self.notes = notes or []

        

    def next_status(self):
        """The only status this incident may move to.

        :return: next status, or None when the incident is Closed
        :rtype: str or None
        """
        return self.NEXT_STATUS.get(self.status)
        

    def can_move_to(self, new_status):
        """Check the lifecycle rule (no skipping, no going back).

        :param new_status: requested status, already checked against STATUSES
        :type new_status: str
        :return: True only if new_status is exactly the next step
        :rtype: bool
        """
        return new_status == self.next_status()
    
    def to_dict(self, include_notes=True):
        """Return the incident as a JSON-ready dict.

        Tip: also return ``next_allowed_status`` so the Postman screenshots show the workflow.

        :param include_notes: add the ``notes`` list (GET /incidents/{id}); the list endpoint
            can leave notes out, defaults to True
        :type include_notes: bool, optional
        :return: incident fields (+ notes)
        :rtype: dict
        """
        data = {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "severity": self.severity,
            "reporter_id": self.reporter_id,
            "asset_id": self.asset_id,
            "assigned_analyst_id": self.assigned_analyst_id,
            "status": self.status,
            "next_allowed_status": self.next_status(),
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
        }

        if include_notes:
            data["notes"] = [note.to_dict() for note in self.notes]

        return data
        
