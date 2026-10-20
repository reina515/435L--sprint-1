from shared.db import get_db
from shared.security import utc_now
from asset_service.models import Asset


# all the sql for the assets table is in here. every value goes through a ? placeholder
# so nothing the user sends ends up directly inside the query (no sql injection)
class AssetRepository:
    def create(self, asset_name, asset_type, ip_address, operating_system, owner_id,
               department, location, criticality_level, status):
        conn = get_db()
        try:
            cur = conn.execute(
                "INSERT INTO assets (asset_name, asset_type, ip_address, operating_system, owner_id, "
                "department, location, criticality_level, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (asset_name, asset_type, ip_address, operating_system, owner_id,
                 department, location, criticality_level, status, utc_now()),
            )
            conn.commit()
            # return the new id so the route can fetch the full asset after inserting
            return cur.lastrowid
        finally:
            conn.close()

    def get_by_id(self, asset_id):
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
            return Asset(row) if row else None
        finally:
            conn.close()

    def update(self, asset_id, fields):
        # fields is a dict like {"status": "Inactive"}. the column names get put into the
        # sql string, so we only keep the ones in this list to be safe
        allowed = ("asset_name", "owner_id", "department",
                   "criticality_level", "status")
        columns = [c for c in fields if c in allowed]
        if not columns:
            return
        assignments = ", ".join(f"{c} = ?" for c in columns)
        conn = get_db()
        try:
            conn.execute(f"UPDATE assets SET {assignments} WHERE asset_id = ?",
                         [fields[c] for c in columns] + [asset_id])
            conn.commit()
        finally:
            conn.close()

    def count_references(self, asset_id):
        # before deleting we check if any incident or vulnerability still points to this asset
        conn = get_db()
        try:
            incidents = conn.execute("SELECT COUNT(*) FROM incidents WHERE asset_id = ?",
                                     (asset_id,)).fetchone()[0]
            vulns = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE asset_id = ?",
                                 (asset_id,)).fetchone()[0]
            return incidents, vulns
        finally:
            conn.close()

    def delete(self, asset_id):
        conn = get_db()
        try:
            cur = conn.execute(
                "DELETE FROM assets WHERE asset_id = ?", (asset_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def search(self, filters, limit, offset):
        # name and department are partial matches (LIKE), the rest have to match exactly.
        # this is also used for "get all assets" by passing an empty filters dict
        where, params = [], []
        for column in ("asset_name", "department"):
            if column in filters:
                # escape % and _ so they are treated as normal characters and not wildcards
                escaped = filters[column].replace("\\", "\\\\").replace(
                    "%", "\\%").replace("_", "\\_")
                where.append(f"{column} LIKE ? ESCAPE '\\'")
                params.append(f"%{escaped}%")
        for column in ("asset_type", "ip_address", "criticality_level"):
            if column in filters:
                where.append(f"{column} = ?")
                params.append(filters[column])
        # if there are no filters "1=1" just matches every row
        clause = " AND ".join(where) if where else "1=1"
        conn = get_db()
        try:
            rows = conn.execute(
                f"SELECT * FROM assets WHERE {clause} ORDER BY asset_id LIMIT ? OFFSET ?",
                params + [limit, offset]).fetchall()
            # total is the count without the limit, so the client knows how many exist overall
            total = conn.execute(
                f"SELECT COUNT(*) FROM assets WHERE {clause}", params).fetchone()[0]
            return [Asset(r) for r in rows], total
        finally:
            conn.close()
