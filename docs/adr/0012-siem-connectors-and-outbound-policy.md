# ADR 0012 — LogRhythm and Trend Vision One connectors; narrow outbound allow-list

**Status:** accepted

**Connectors.** `logrhythm` (Search API: search-task → poll search-result) and `trend_vision_one` (one data source per dataset:
`alerts`, `oat`, `endpoint_activity`, `detections`) are pull connectors. Both read oldest-first in fixed time windows and emit
only *whole* windows, so the scheduler `watermark` can advance past quiet periods without skipping data; a 10-minute overlap plus
deterministic event ids (`original_id`) make re-reads idempotent. A window that returns too much (LogRhythm's 30,000-log cap,
Trend's page budget) is split in half and retried. Each run has a time budget and an event cap; the worker runs sources
concurrently so a slow upstream cannot starve the rest. Transient errors (429/5xx) back off and honour `Retry-After`; 401/403 fail
fast with a message that never contains the credential.

**Mapping.** LogRhythm classification → canonical type (authentication success/failure, alert for AI-Engine/security
classes, network/DNS/file/registry, else `other`); ATT&CK ids in rule names become `attack.tXXXX` tags. LogRhythm's `logDate`
carries the console's UTC offset, so event time is `logDate + date_shift_hours`; search windows are sent in true UTC time (the API filters on true time, not on the shifted `logDate`).
Trend `eventId` 1/2/3/4 map to process/file/network/DNS (for process events `object*` is the new process and `process*` its
parent); Workbench alerts, OAT and product detections become `alert` events. Malformed IPs/hashes are dropped, not fatal.

**Outbound policy.** Private/loopback targets stay blocked. An on-prem SIEM is reached through `OUTBOUND_ALLOWED_NETWORKS`
(specific CIDRs, nothing broader than /16) plus `OUTBOUND_ALLOWED_PORTS`; unlike `OUTBOUND_ALLOW_PRIVATE` this is permitted in
production, and a DNS answer mixing allowed and forbidden addresses is still refused. TLS verification is on by default.
For appliances with self-signed certificates a source can pin the certificate (`ca_pem`) and verify it against a hostname
(`tls_server_name`) while connecting by IP; `verify_tls=false` exists as an explicit, per-source opt-out.

**Credentials.** Stored encrypted per data source; set or rotated one name at a time with a write-only endpoint
(`PUT /data-sources/{id}/secrets/{name}`), never returned, audited without the value.

**Trend datasets.** Besides alerts/OAT/endpoint/detections: `identity_activity` (Entra ID sign-ins → authentication events, directory
audit → other), `audit_logs` (console audit trail; no API id, so a content hash is used), `response_tasks` (snapshot, one event per
status change), and best-effort `email`/`mobile`/`network`/`cloud`/`container` activity (empty or unavailable on the tested tenant).
Page size and window default per dataset (endpoint telemetry: 500/page, 3-minute windows). Capacity is the operator's call: endpoint
telemetry measured at roughly 1.8 KB and 50 events/s per mid-size tenant, i.e. several GB per day.

**Not in scope:** Trend endpoint inventory (returns 400 on the tested tenant), email/cloud activity, alert status updates after
first ingest (alerts are de-duplicated by id), LogRhythm raw-log retrieval.
