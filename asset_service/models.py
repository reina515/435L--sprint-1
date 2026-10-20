class Asset:
    # wraps one row from the assets table so the routes can use asset.asset_name
    # instead of row["asset_name"] everywhere

    def __init__(self, row):
        self.asset_id = row["asset_id"]
        self.asset_name = row["asset_name"]
        self.asset_type = row["asset_type"]
        self.ip_address = row["ip_address"]
        self.operating_system = row["operating_system"]
        self.owner_id = row["owner_id"]
        self.department = row["department"]
        self.location = row["location"]
        self.criticality_level = row["criticality_level"]
        self.status = row["status"]
        self.created_at = row["created_at"]

    # used when sending the asset back in the json response
    def to_dict(self):
        return {
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "asset_type": self.asset_type,
            "ip_address": self.ip_address,
            "operating_system": self.operating_system,
            "owner_id": self.owner_id,
            "department": self.department,
            "location": self.location,
            "criticality_level": self.criticality_level,
            "status": self.status,
            "created_at": self.created_at,
        }
