# ADR 0010 — Detection engineering

**Status:** accepted (Milestone 5)

**Formats compile to one executable form.** A `DetectionFormat` (Sigma, hunt query) parses rule text into a `ParsedRule`:
metadata plus a `Condition` tree (all / any / not / validated `Filter`). The same tree is compiled by the OpenSearch backend
(`EventQuery.where`, ANDed inside the tenant-scoped nested bool, so a rule can narrow but never widen tenant scope) and
evaluated by a reference evaluator (`events/search/local.py`) used for rule unit tests. A differential test keeps the two
in lock-step. Rules are untrusted input: YAML is loaded with a safe loader, no anchors/aliases, bounded size/depth, and
conditions are bounded in depth and node count.

**Never approximate.** Constructs we cannot execute faithfully (regex, base64 modifiers, `count()`/`near` aggregations,
unmapped fields or logsources, free-text hunt queries) go to `unsupported`. Such a rule is stored but has no compiled form and
can never leave DRAFT. Warnings are surfaced, not hidden.

**Lifecycle.** DRAFT → TESTING → ACTIVE ⇄ DISABLED, any → ARCHIVED. ACTIVE requires an executable rule, at least one
must-match test case, and a passing test run *for the current version*. Saving new content (new immutable `RuleVersion`) or
changing the test set drops the rule out of ACTIVE. Activating/disabling needs `detections:manage` (tenant admin, threat
hunter); authoring, testing, backtesting and alert triage need `detections:write`.

**Execution.** A worker cron evaluates ACTIVE rules every 5 minutes against events *ingested* since the last run
(`ingested_at`, with a 90 s overlap for search-visibility lag; floor = activation time, so activation never floods
historical alerts). Alerts are unique per (rule, event) — re-reads are idempotent — and snapshot the event so they outlive
retention. A failing rule records `last_run_error` and never blocks other rules. Backtests count matches over a chosen
window and never raise alerts. Per-run alert volume is capped (1000); the remainder is picked up next run.

**Integration.** Hunt → detection wraps the hunt query in the `hunt_query` format as a DRAFT linked to the hunt. Rule ATT&CK
tags become LOW-confidence `MitreMapping`s (a declaration, not telemetry evidence). Alerts escalate to a case seeded with the
matching event. Every mutation is audited.

**Not in scope:** correlation / aggregation rules, rule sharing across tenants, alert deduplication windows, notifications.
