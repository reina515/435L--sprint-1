"""
Playbook and response action models (Security Playbook and Response Automation Service).
Implemented by: Hayam Itani
"""


class ResponseAction:
    """One row of the ``response_actions`` table (one ordered step of a playbook).

    :param row: a row from ``SELECT * FROM response_actions``
    :type row: sqlite3.Row
    """

    STATUSES = ("Pending", "In Progress", "Completed")

    # Forward only, one step at a time; Completed is final
    NEXT_STATUS = {
        "Pending": "In Progress",
        "In Progress": "Completed",
    }


    def __init__(self, row):
        """Constructor method"""
        self.action_id = row["action_id"]
        self.playbook_id = row["playbook_id"]
        self.description = row["description"]
        self.step_number = row["step_number"]
        self.status = row["status"]
        self.assigned_user_id = row["assigned_user_id"]
        self.completed_at = row["completed_at"]


    @property
    def is_completed(self):
        """Whether this step is finished.

        :return: True when the status is Completed
        :rtype: bool
        """
        return self.status == "Completed"


    def can_move_to(self, new_status):
        """Forward one step only (D4).

        :param new_status: one of STATUSES
        :type new_status: str
        :return: True if allowed
        :rtype: bool
        """
        return self.NEXT_STATUS.get(self.status) == new_status


    def to_dict(self):
        """Return the action as a JSON-ready dict.

        :return: the 7 attributes above
        :rtype: dict
        """
        return {
            "action_id": self.action_id,
            "playbook_id": self.playbook_id,
            "description": self.description,
            "step_number": self.step_number,
            "status": self.status,
            "assigned_user_id": self.assigned_user_id,
            "completed_at": self.completed_at,
        }



class Playbook:
    """One row of the ``playbooks`` table plus its ordered response actions.

    :param row: a row from ``SELECT * FROM playbooks``
    :type row: sqlite3.Row
    :param actions: actions sorted by step_number, defaults to None
    :type actions: list[ResponseAction], optional
    """

    def __init__(self, row, actions=None):
        """Constructor method"""
        self.playbook_id = row["playbook_id"]
        self.name = row["name"]
        self.description = row["description"]
        self.incident_category = row["incident_category"]
        self.severity = row["severity"]
        self.created_by = row["created_by"]
        self.created_at = row["created_at"]
        self.actions = actions or []


    def progress(self):
        """Optional but nice in screenshots: how many steps are done.

        :return: e.g. {"completed": 1, "total": 3}
        :rtype: dict
        """
        completed = sum(1 for action in self.actions if action.is_completed)
        return {"completed": completed, "total": len(self.actions)}


    def to_dict(self, include_actions=True):
        """Return the playbook as a JSON-ready dict.

        :param include_actions: add the ordered ``actions`` list (GET /playbooks/{id}),
            defaults to True
        :type include_actions: bool, optional
        :return: playbook fields (+ actions, action_count, progress)
        :rtype: dict
        """
        data = {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "incident_category": self.incident_category,
            "severity": self.severity,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "action_count": len(self.actions),
            "progress": self.progress(),
        }
        if include_actions:
            data["actions"] = [action.to_dict() for action in self.actions]
        return data

