import ipaddress

from shared.errors import ValidationError

# the only values we accept for these fields
ASSET_TYPES = ("Server", "Workstation", "Database",
               "Application", "Network Device", "Cloud Resource")
CRITICALITY_LEVELS = ("Low", "Medium", "High", "Critical")
ASSET_STATUSES = ("Active", "Inactive", "Under Maintenance")


def validate_ip(value, field="ip_address"):
    if not isinstance(value, str):
        raise ValidationError(f"'{field}' must be a string")
    # python's ipaddress module does the actual checking (works for ipv4 and ipv6),
    # so something like 999.1.1.1 gets rejected
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ValidationError("Invalid IP address format")
