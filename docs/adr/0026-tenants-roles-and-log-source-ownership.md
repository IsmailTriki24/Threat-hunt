# ADR 0026 — Platform operator, tenants and who owns a log source

**Status:** accepted. Builds on the tenant model of `ARCHITECTURE.md` §4; changes who may manage data sources.

**Problem.** The platform serves several organisations (today Wifak Bank, with LogRhythm and Trend Vision One; more tenants and other log
sources later). Each log source needs credentials to a SIEM that belongs to the organisation's security estate, yet nothing said who attaches a
source to a tenant: any tenant admin could create one and read its configuration, and the platform operator had no cross-tenant view of members,
sources or audit.

**Decision.** Two levels of authority, one permission table (`auth/rbac.py`):

| Level | Role | Can |
|---|---|---|
| Platform | `SUPER_ADMIN` (a `users.is_super_admin` flag, never a membership; CLI-created only) | create / disable tenants, create tenant admins and manage any tenant's members (role, deactivate, password reset), **create and configure every tenant's log sources and credentials**, read the audit trail of every tenant, act inside any tenant with every tenant permission |
| Tenant | `TENANT_ADMIN` | manage the tenant's users, feeds, IOC validation, read log sources and their health |
| Tenant | `SOC_ANALYST`, `THREAT_HUNTER`, `INCIDENT_RESPONDER` | hunt, investigate, work cases and detections; read log sources |
| Tenant | `VIEWER` | read-only; no log-source view |

* `PLATFORM_PERMISSIONS` = `tenants:manage`, `audit:platform`, `datasources:manage`. No tenant role holds any of them (`tests/test_rbac.py`).
  Log sources are **assigned by the operator**: a tenant admin sees a source's name, health and counts but cannot create, edit, delete, rotate its
  ingest key, set a credential, test or collect it. Credentials were already write-only and encrypted; they are now also operator-only.
* The operator manages a tenant's log sources by *opening* the tenant (`POST /auth/switch-tenant`, audited), so the data-source API keeps a single
  code path and a tenant id is still never taken from a request body. Tenant-targeted platform routes (`/tenants/{id}/members`, `/audit/platform`)
  take the id from the path and require `tenants:manage` / `audit:platform`, which only the operator has.
* A tenant always keeps one active `TENANT_ADMIN`: demoting or deactivating the last one is refused (409), by either router.
* One person may belong to several tenants with a different role in each. Only the operator can attach an existing account to another tenant; a
  tenant admin creating a user with a known e-mail still gets 409 (no cross-tenant enumeration or takeover).
* A password reset by the operator revokes the user's refresh tokens everywhere; a deactivation revokes them for that tenant.
* Production bootstrap needs no demo seed: `python -m app.cli create-superadmin <email>` then `python -m app.cli create-tenant <slug> <name> <admin-email>`
  (the API uses the same `tenants.service.provision_tenant`). A tenant that is already configured moves between deployments with
  `export-tenant` / `import-tenant` (`tenants/bundle.py`): members and log sources with credentials in one passphrase-sealed file, credentials
  re-encrypted under the target's key, import refuses an existing slug and is all-or-nothing.

**Chosen on purpose.** The operator keeps full read access to a tenant's security data while acting inside it (decided with the owner), rather than a
"platform only, no data" role. Every switch into a tenant and every member/tenant change is audited (`auth.switch_tenant`, `tenant.*`), and
`/audit/platform` shows them across tenants. If a customer later requires that the operator cannot read their events, add an explicit
`tenant.operator_access` flag checked in `get_principal`; nothing here prevents it.

**Not done.** SSO/MFA, per-tenant connector-type entitlements (a tenant is limited only by what the operator attaches), custom roles, and
automated password-reset e-mail.
