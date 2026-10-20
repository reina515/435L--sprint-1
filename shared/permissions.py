ADMIN = "Security Administrator"
ANALYST = "Security Analyst"
EMPLOYEE = "Regular Employee"
AUDITOR = "Auditor"

ALL = "all"
OWN = "own"

PERMISSIONS = {
    "users:register":      {ADMIN: ALL, EMPLOYEE: ALL},
    "users:logout":        {ADMIN: ALL, ANALYST: ALL, EMPLOYEE: ALL, AUDITOR: ALL},
    "users:update":        {ADMIN: ALL, EMPLOYEE: OWN},
    "users:change_role":   {ADMIN: ALL},
    "users:change_status": {ADMIN: ALL},
    "users:delete":        {ADMIN: ALL},
    "users:list":          {ADMIN: ALL, AUDITOR: ALL},
    "users:view":          {ADMIN: ALL, AUDITOR: ALL, EMPLOYEE: OWN},
    "roles:view":          {ADMIN: ALL, AUDITOR: ALL},

    "logs:create":         {ADMIN: ALL},
    "logs:list":           {ADMIN: ALL, AUDITOR: ALL},
    "logs:view":           {ADMIN: ALL, AUDITOR: ALL, ANALYST: ALL},
    "logs:search":         {ADMIN: ALL, AUDITOR: ALL, ANALYST: ALL},
    "logs:delete":         {ADMIN: ALL},
    "logs:by_user":        {ADMIN: ALL, AUDITOR: ALL},

    "notifications:create":    {ADMIN: ALL},
    "notifications:by_user":   {ADMIN: ALL, AUDITOR: ALL, ANALYST: OWN, EMPLOYEE: OWN},
    "notifications:view":      {ADMIN: ALL, AUDITOR: ALL, ANALYST: OWN, EMPLOYEE: OWN},
    "notifications:mark_read": {ADMIN: ALL, ANALYST: OWN, EMPLOYEE: OWN},
    "notifications:search":    {ADMIN: ALL, AUDITOR: ALL, ANALYST: OWN},
    "notifications:delete":    {ADMIN: ALL},

    #---------------- Service 3: Incident Management ----------------
    "incidents:create":        {ADMIN: ALL, EMPLOYEE: ALL},
    "incidents:list":          {ADMIN: ALL, AUDITOR: ALL, ANALYST: OWN, EMPLOYEE: OWN},
    "incidents:view":          {ADMIN: ALL, AUDITOR: ALL, ANALYST: OWN, EMPLOYEE: OWN},
    "incidents:assign":        {ADMIN: ALL},
    "incidents:status":        {ADMIN: ALL, ANALYST: OWN},
    "incidents:add_note":      {ADMIN: ALL, ANALYST: OWN},

    #---------------- Service 4: Threat Intelligence ----------------
    "threats:create":          {ADMIN: ALL},
    "threats:list":            {ADMIN: ALL, AUDITOR: ALL, ANALYST: ALL},
    "threats:view":            {ADMIN: ALL, AUDITOR: ALL, ANALYST: ALL},
    "threats:search":          {ADMIN: ALL, AUDITOR: ALL, ANALYST: ALL},
    "threats:update":          {ADMIN: ALL},
    "threats:delete":          {ADMIN: ALL},

    # ---------------- Service 9: Playbooks and Response----------------
    "playbooks:create":        {ADMIN: ALL},
    "playbooks:list":          {ADMIN: ALL, AUDITOR: ALL, ANALYST: ALL},
    "playbooks:view":          {ADMIN: ALL, AUDITOR: ALL, ANALYST: ALL},
    "playbooks:add_action":        {ADMIN: ALL, ANALYST: ALL},
    "actions:update_status":        {ADMIN: ALL, ANALYST: ALL},
    "playbooks:delete":        {ADMIN: ALL},
}


# looks up if a role can use a permission and if it is for all records or only its own
def scope_for(role, permission):
    return PERMISSIONS.get(permission, {}).get(role)


# flips the permissions table so each role shows the list of things it can do
def permissions_by_role():
    result = {role: {} for role in (ADMIN, ANALYST, EMPLOYEE, AUDITOR)}
    for permission, roles in PERMISSIONS.items():
        for role, scope in roles.items():
            result[role][permission] = scope
    return result
