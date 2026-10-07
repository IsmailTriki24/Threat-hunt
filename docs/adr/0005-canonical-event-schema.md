# ADR 0005 — Canonical event schema v1

**Status:** accepted

ECS-inspired, with deliberate differences: explicit `schema_version`, `event_type` as a closed enum
(`process_creation`, `network_connection`, `dns_query`, `file_event`, `authentication`, …) driving index
family routing, a flat `severity` (0–100), an `auth` section (logon type/method/source) and `registry`
section, `labels` (flat_object, unindexed-by-registry) for source-specific extras, and `raw` (stored,
not indexed, ≤64 KiB) for evidence fidelity. Normalizers produce `EventIn` (no tenant); the server stamps
`tenant_id`, `id`, `ingested_at`.

Keyword fields use a lowercase normalizer (case-insensitive hostnames/users/hashes; aggregation keys come back
lower-cased; `raw` preserves originals). Command lines/paths use a `cmd` analyzer that tokenises on non-alphanumerics
so `powershell`, `enc`, `downloadstring` are individually searchable.

Index families: `events-` (other), `endpoint-`, `network-`, `authentication-`, `dns-`, daily suffix `YYYY.MM.DD`;
one composable index template. Schema evolution: add fields to the registry (additive); breaking changes bump
`SCHEMA_VERSION` and are handled by reindex.
