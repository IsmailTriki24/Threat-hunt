# ADR 0008 — Cases, evidence snapshots, assets, data sources

**Status:** accepted

**Cases.** `cases` + `case_evidence` / `case_iocs` / `case_assets` / `case_activity` / `case_reports`. Human ids (`CASE-0001`) come from a
per-tenant counter updated with an atomic upsert (no gaps under concurrency, no cross-tenant visibility of volume). Status changes
go exclusively through `cases/workflow.py` (state machine; RESOLVED / FALSE_POSITIVE / CLOSED and reopen require a comment;
CLOSED cases are locked). Assignees must be active members of the tenant with `cases:write`.

**Evidence is snapshotted.** Adding an event stores its full document (minus `raw`) so the case, its timeline and reports stay
reconstructable after telemetry retention deletes the originals. Event ids are verified against the caller's tenant before use.
IOCs and assets are derived at add-time (`investigations/iocs.py` — validated, normalised, internal addresses skipped, linear-time
regexes, length-capped input) and can be re-extracted; manual IOCs survive re-extraction.

**Case timeline** rebuilds from live telemetry where it still exists and from snapshots otherwise, using the same pure
`timeline.build` as hunts (ADR 0007). The case journal (`case_activity`) is separate from the security `audit_logs` (which stays
append-only and trigger-protected); case audit views join the two by `resource_type='case'`.

**Reports** are generated Markdown, versioned and immutable (`case_reports`), with table-cell escaping. Storage in MinIO/PDF export
is deferred until there is a consumer that needs files rather than text.

**Assets.** Identity = (tenant, type, normalised key). Relationships are *derived from telemetry* on request (aggregations), not
stored, so they cannot go stale; only case ↔ asset links are persisted. `discover` upserts hosts/users/internal IPs from
aggregations; analyst-set fields (criticality, owner, tags) are never overwritten.

**Data sources.** Persisted per tenant; connector config is validated by the connector's pydantic model; secrets are Fernet-encrypted
(`DATA_ENCRYPTION_KEY`, required in production) and never returned. Push sources authenticate with a per-source ingest key
(`hk_…`, 256-bit, only its SHA-256 stored, shown once, rotatable). The key resolves to the source and therefore the tenant — the
caller never names a tenant — and the path id must match the key. Pull sources run on a worker cron through `core/ssrf.py`.

**SSRF.** `core/ssrf.py`: scheme/port allow-list, DNS resolved once and every address required to be public, connection pinned to the
validated IP with original Host/SNI (no DNS-rebinding window), manual re-validated redirects, credentials stripped on cross-host
redirects, response size cap. Private targets can be enabled only via `OUTBOUND_ALLOW_PRIVATE` (refused in production). Milestone 4
enrichment adapters must use it too.
