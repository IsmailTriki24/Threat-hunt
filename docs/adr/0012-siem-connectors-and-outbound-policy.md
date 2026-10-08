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
carries the console's UTC offset, so event time is `logDate + date_shift_hours` and the same shift is applied to search windows.
Trend `eventId` 1/2/3/4 map to process/file/network/DNS (for process events `object*` is the new process and `process*` its
parent); Workbench alerts, OAT and product detections become `alert` events. Malformed IPs/hashes are dropped, not fatal.

**Outbound policy.** Private/loopback targets stay blocked. An on-prem SIEM is reached through `OUTBOUND_ALLOWED_NETWORKS`
(specific CIDRs, nothing broader than /16) plus `OUTBOUND_ALLOWED_PORTS`; unlike `OUTBOUND_ALLOW_PRIVATE` this is permitted in
production, and a DNS answer mixing allowed and forbidden addresses is still refused. TLS verification is on by default.
For appliances with self-signed certificates a source can pin the certificate (`ca_pem`) and verify it against a hostname
(`tls_server_name`) while connecting by IP; `verify_tls=false` exists as an explicit, per-source opt-out.

**Credentials.** Stored encrypted per data source; set or rotated one name at a time with a write-only endpoint
(`PUT /data-sources/{id}/secrets/{name}`), never returned, audited without the value.

**Not in scope:** Trend endpoint inventory (returns 400 on the tested tenant), email/cloud activity, alert status updates after
first ingest (alerts are de-duplicated by id), LogRhythm raw-log retrieval.
