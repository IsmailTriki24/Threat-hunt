"""Role → permission model. Single source of truth; enforced server-side by `require()`."""

from enum import StrEnum


class Role(StrEnum):
    SUPER_ADMIN = "SUPER_ADMIN"
    TENANT_ADMIN = "TENANT_ADMIN"
    SOC_ANALYST = "SOC_ANALYST"
    THREAT_HUNTER = "THREAT_HUNTER"
    INCIDENT_RESPONDER = "INCIDENT_RESPONDER"
    VIEWER = "VIEWER"


TENANT_ROLES = [r for r in Role if r is not Role.SUPER_ADMIN]


class Permission(StrEnum):
    EVENTS_READ = "events:read"
    EVENTS_INGEST = "events:ingest"
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"
    AUDIT_READ = "audit:read"
    HUNTS_READ = "hunts:read"
    HUNTS_WRITE = "hunts:write"
    HUNTS_DELETE = "hunts:delete"
    CASES_READ = "cases:read"
    CASES_WRITE = "cases:write"
    ASSETS_READ = "assets:read"
    ASSETS_WRITE = "assets:write"
    DATASOURCES_READ = "datasources:read"
    DATASOURCES_MANAGE = "datasources:manage"
    INTEL_READ = "intel:read"
    INTEL_WRITE = "intel:write"
    INTEL_MANAGE = "intel:manage"
    MITRE_READ = "mitre:read"
    MITRE_WRITE = "mitre:write"
    TENANTS_MANAGE = "tenants:manage"  # platform-wide: create/disable tenants


_ANALYST = {
    Permission.EVENTS_READ,
    Permission.HUNTS_READ,
    Permission.HUNTS_WRITE,
    Permission.CASES_READ,
    Permission.CASES_WRITE,
    Permission.ASSETS_READ,
    Permission.ASSETS_WRITE,
    Permission.DATASOURCES_READ,
    Permission.INTEL_READ,
    Permission.INTEL_WRITE,
    Permission.MITRE_READ,
    Permission.MITRE_WRITE,
}

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset(
        {
            Permission.EVENTS_READ,
            Permission.HUNTS_READ,
            Permission.CASES_READ,
            Permission.ASSETS_READ,
            Permission.INTEL_READ,
            Permission.MITRE_READ,
        }
    ),
    Role.SOC_ANALYST: frozenset(_ANALYST),
    Role.THREAT_HUNTER: frozenset(_ANALYST | {Permission.HUNTS_DELETE}),
    Role.INCIDENT_RESPONDER: frozenset(_ANALYST),
    Role.TENANT_ADMIN: frozenset(
        {
            Permission.EVENTS_READ,
            Permission.EVENTS_INGEST,
            Permission.USERS_READ,
            Permission.USERS_MANAGE,
            Permission.AUDIT_READ,
            Permission.HUNTS_READ,
            Permission.HUNTS_WRITE,
            Permission.HUNTS_DELETE,
            Permission.CASES_READ,
            Permission.CASES_WRITE,
            Permission.ASSETS_READ,
            Permission.ASSETS_WRITE,
            Permission.DATASOURCES_READ,
            Permission.DATASOURCES_MANAGE,
            Permission.INTEL_READ,
            Permission.INTEL_WRITE,
            Permission.INTEL_MANAGE,
            Permission.MITRE_READ,
            Permission.MITRE_WRITE,
        }
    ),
    Role.SUPER_ADMIN: frozenset(Permission),
}


def permissions_for(role: Role) -> frozenset[Permission]:
    return ROLE_PERMISSIONS[role]
