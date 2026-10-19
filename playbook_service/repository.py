"""
Database access for the playbooks and response_actions tables.
Implemented by: Hayam Itani

Schema facts you rely on:
  * response_actions.playbook_id -> playbooks ON DELETE CASCADE (deleting a playbook deletes its steps)
  * UNIQUE (playbook_id, step_number)  -> duplicate step = sqlite3.IntegrityError
  * CHECK (step_number > 0)
Parameterised queries only (?).
"""
from shared.db import get_db
from shared.security import utc_now
from playbook_service.models import Playbook, ResponseAction


class PlaybookRepository:
    """All SQL of the Playbook and Response Automation Service."""

    # ---------------------------------------------------------------- playbooks
    def create(self, name, description, incident_category, severity, created_by):
        """Insert a new playbook.

        :param name: playbook name
        :type name: str
        :param description: what the playbook is for
        :type description: str
        :param incident_category: one of INCIDENT_CATEGORIES
        :type incident_category: str
        :param severity: Low, Medium, High or Critical
        :type severity: str
        :param created_by: user id of the administrator creating it
        :type created_by: int
        :return: the new playbook_id
        :rtype: int
        """
        conn = get_db()
        try:
            cur = conn.execute(
                "INSERT INTO playbooks (name, description, incident_category, severity, created_by, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (name, description, incident_category, severity, created_by, utc_now()),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


    def get_by_id(self, playbook_id):
        """Playbook with its actions ordered by step_number.

        :param playbook_id: id of the playbook
        :type playbook_id: int
        :return: Playbook or None
        :rtype: Playbook or None
        """
        conn = get_db()
        try:
            row = conn.execute("SELECT * FROM playbooks WHERE playbook_id = ?", (playbook_id,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return Playbook(row, self.get_actions(playbook_id))


    def list(self, filters, limit, offset):
        """List playbooks, newest first.

        :param filters: may contain incident_category, severity
        :type filters: dict
        :param limit: page size
        :type limit: int
        :param offset: rows to skip
        :type offset: int
        :return: (playbooks, total)
        :rtype: tuple[list[Playbook], int]
        """
        allowed = ("incident_category", "severity")
        where, params = [], []
        for column in allowed:
            if column in filters:
                where.append(f"{column} = ?")
                params.append(filters[column])
        clause = " AND ".join(where) if where else "1=1"
        conn = get_db()
        try:
            rows = conn.execute(f"SELECT * FROM playbooks WHERE {clause} "
                                f"ORDER BY playbook_id DESC LIMIT ? OFFSET ?",
                                params + [limit, offset]).fetchall()
            total = conn.execute(f"SELECT COUNT(*) FROM playbooks WHERE {clause}", params).fetchone()[0]
        finally:
            conn.close()
        return [Playbook(r, self.get_actions(r["playbook_id"])) for r in rows], total


    def delete(self, playbook_id):
        """Delete a playbook; its actions go with it (CASCADE).

        :param playbook_id: id of the playbook
        :type playbook_id: int
        :return: True if a row was deleted
        :rtype: bool
        """
        conn = get_db()
        try:
            cur = conn.execute("DELETE FROM playbooks WHERE playbook_id = ?", (playbook_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


    # ---------------------------------------------------------------- actions
    def get_actions(self, playbook_id):
        """All actions of one playbook, in step order.

        :param playbook_id: id of the playbook
        :type playbook_id: int
        :return: actions ORDER BY step_number
        :rtype: list[ResponseAction]
        """
        conn = get_db()
        try:
            rows = conn.execute("SELECT * FROM response_actions WHERE playbook_id = ? ORDER BY step_number",
                                (playbook_id,)).fetchall()
        finally:
            conn.close()
        return [ResponseAction(r) for r in rows]


    def get_action(self, action_id):
        """Load one response action.

        :param action_id: id of the action
        :type action_id: int
        :return: the action, or None if it does not exist
        :rtype: ResponseAction or None
        """
        conn = get_db()
        try:
            row = conn.execute("SELECT * FROM response_actions WHERE action_id = ?", (action_id,)).fetchone()
        finally:
            conn.close()
        return ResponseAction(row) if row else None



    def add_action(self, playbook_id, description, step_number, assigned_user_id):
        """New step with status 'Pending'.

        :param playbook_id: id of the playbook the step belongs to
        :type playbook_id: int
        :param description: what has to be done in this step
        :type description: str
        :param step_number: position of the step (1, 2, 3, ...), unique per playbook
        :type step_number: int
        :param assigned_user_id: user responsible for the step, or None
        :type assigned_user_id: int or None
        :return: the new action_id
        :rtype: int
        :raises sqlite3.IntegrityError: step_number already used in this playbook
        """
        conn = get_db()
        try:
            cur = conn.execute(
                "INSERT INTO response_actions (playbook_id, description, step_number, status, assigned_user_id) "
                "VALUES (?, ?, ?, 'Pending', ?)",
                (playbook_id, description, step_number, assigned_user_id),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


    def unfinished_steps_before(self, playbook_id, step_number):
        """D4 ordering rule: steps with a LOWER step_number that are not Completed yet.

        :param playbook_id: id of the playbook
        :type playbook_id: int
        :param step_number: the step that wants to start
        :type step_number: int
        :return: their step numbers (empty list = this step may start)
        :rtype: list[int]
        """
        conn = get_db()
        try:
            rows = conn.execute("SELECT step_number FROM response_actions WHERE playbook_id = ? "
                                "AND step_number < ? AND status != 'Completed' ORDER BY step_number",
                                (playbook_id, step_number)).fetchall()
        finally:
            conn.close()
        return [r["step_number"] for r in rows]


    def update_action(self, action_id, status, assigned_user_id, completed_at):
        """Write the new values of one action (the route has already validated them).

        :param action_id: id of the action
        :type action_id: int
        :param status: Pending, In Progress or Completed
        :type status: str
        :param assigned_user_id: user responsible for the step, or None
        :type assigned_user_id: int or None
        :param completed_at: completion timestamp, or None while not completed
        :type completed_at: str or None
        """
        conn = get_db()
        try:
            conn.execute("UPDATE response_actions SET status = ?, assigned_user_id = ?, completed_at = ? "
                         "WHERE action_id = ?", (status, assigned_user_id, completed_at, action_id))
            conn.commit()
        finally:
            conn.close()

