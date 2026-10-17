"""
Role-Based Access Control (RBAC) matrix - the single source of truth.

Every protected route is decorated with @require_permission("<name>") and the
decorator looks the permission up here.  The value says which roles may use it
and with which scope:

    ALL -> the role may act on any record
    OWN -> the role may only act on its own records (own profile, own notifications)

A role that is not listed for a permission is rejected with 403 and the attempt
is written to the Security Audit Logging Service.
"""

ADMIN = "Security Administrator"
ANALYST = "Security Analyst"
EMPLOYEE = "Regular Employee"
AUDITOR = "Auditor"

ALL = "all"
OWN = "own"

PERMISSIONS = {
    # ---------------- Service 1: Users and Identity Management ----------------
    "users:register":      {ADMIN: ALL, EMPLOYEE: ALL},     # (also open to anonymous visitors)
    "users:logout":        {ADMIN: ALL, ANALYST: ALL, EMPLOYEE: ALL, AUDITOR: ALL},
    "users:update":        {ADMIN: ALL, EMPLOYEE: OWN},
    "users:change_role":   {ADMIN: ALL},
    "users:change_status": {ADMIN: ALL},
    "users:delete":        {ADMIN: ALL},
    "users:list":          {ADMIN: ALL, AUDITOR: ALL},
    "users:view":          {ADMIN: ALL, AUDITOR: ALL, EMPLOYEE: OWN},
    "roles:view":          {ADMIN: ALL, AUDITOR: ALL},

    # ---------------- Service 5: Security Audit Logging ----------------
    "logs:create":         {ADMIN: ALL},
    "logs:list":           {ADMIN: ALL, AUDITOR: ALL},
    "logs:view":           {ADMIN: ALL, AUDITOR: ALL, ANALYST: ALL},
    "logs:search":         {ADMIN: ALL, AUDITOR: ALL, ANALYST: ALL},
    "logs:delete":         {ADMIN: ALL},
    "logs:by_user":        {ADMIN: ALL, AUDITOR: ALL},

    # ---------------- Service 8: Notification and Alert Management ----------------
    "notifications:create":    {ADMIN: ALL},
    "notifications:by_user":   {ADMIN: ALL, AUDITOR: ALL, ANALYST: OWN, EMPLOYEE: OWN},
    "notifications:view":      {ADMIN: ALL, AUDITOR: ALL, ANALYST: OWN, EMPLOYEE: OWN},
    "notifications:mark_read": {ADMIN: ALL, ANALYST: OWN, EMPLOYEE: OWN},
    "notifications:search":    {ADMIN: ALL, AUDITOR: ALL, ANALYST: OWN},
    "notifications:delete":    {ADMIN: ALL},
}


def scope_for(role, permission):
    """Return ALL, OWN, or None (= not allowed)."""
    return PERMISSIONS.get(permission, {}).get(role)


def permissions_by_role():
    """{role: {permission: scope}} - returned by GET /roles."""
    result = {role: {} for role in (ADMIN, ANALYST, EMPLOYEE, AUDITOR)}
    for permission, roles in PERMISSIONS.items():
        for role, scope in roles.items():
            result[role][permission] = scope
    return result
