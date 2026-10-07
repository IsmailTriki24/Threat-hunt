# ADR 0002 — Tenant isolation

**Status:** accepted

## Decision
1. **Tenant context is derived, never supplied.** The access token carries a `tid` *hint*; on every request
   the server re-validates `user → active membership → active tenant` in PostgreSQL and takes the **role from
   the database**, not from the token. Revoking a membership or deactivating a tenant takes effect immediately.
   No endpoint accepts a tenant id as input for tenant-scoped data (request models are `extra="forbid"`).
2. **Relational data**: every tenant-owned table has `tenant_id`; handlers filter by `principal.tid`. A row from
   another tenant is indistinguishable from a missing row (404).
3. **Telemetry**: shared daily indices (`events-*`, `network-*`, …) with a mandatory `tenant_id` term filter.
   `SearchBackend` methods take `tenant_id` explicitly; the compiler puts the tenant filter at the top level
   of the bool query and nests all user-controlled clauses in a sub-`bool`, so user input can only narrow.
   Event ids are `sha256(tenant|source|native_id)` so identical native ids in two tenants never collide.
4. **SUPER_ADMIN** is a platform flag on the user, not a tenant role. It operates tenant data only after
   selecting a tenant (`switch-tenant`), which is audited.

## Alternatives considered
* *Index-per-tenant*: strongest physical isolation, but shard explosion with many tenants. Documented upgrade
  path: the `SearchBackend` seam allows routing large tenants to dedicated indices without API changes.
* *OpenSearch document-level security*: requires the security plugin; planned for production hardening as
  defence in depth (see SECURITY.md), not as the primary control.

## Tests
`backend/tests/test_tenant_isolation.py` attacks search, aggregation, detail lookup, ingest, user management,
tenant switching, token tampering and retention deletion across tenants.
