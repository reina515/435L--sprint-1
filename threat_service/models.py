"""
Threat indicator model (Threat Intelligence Service).
Implemented by: Hayam Itani
"""


class Threat:
    """One row of the ``threats`` table.

    :param row: a row from ``SELECT * FROM threats``
    :type row: sqlite3.Row
    """

    # Must match the CHECK constraint in database/schema.sql exactly (D5: "Other", not "Other indicators")
    TYPES = ("IP Address", "Domain", "File Hash", "Malware Signature", "Other")

    def __init__(self, row):
        """Constructor method"""
        self.threat_id = row["threat_id"]
        self.threat_type = row["threat_type"]
        self.threat_value = row["threat_value"]
        self.description = row["description"]
        self.severity = row["severity"]
        self.source = row["source"]
        self.date_added = row["date_added"]


    def to_dict(self):
        """Return the threat as a JSON-ready dict.

        :return: the 7 attributes above
        :rtype: dict
        """
        return {
            "threat_id": self.threat_id,
            "threat_type": self.threat_type,
            "threat_value": self.threat_value,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "date_added": self.date_added,
        }
