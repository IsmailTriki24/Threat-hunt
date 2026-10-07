# ADR 0007 — Hunt query language and telemetry-derived timeline

**Status:** accepted

**Query language.** Analysts type `process.parent.name:WINWORD.EXE -user.name:svc_* network.dst_port>=1024 enc*`.
`events/search/dsl.py` parses it into free text + `Filter` objects — the *same* validated model the structured API uses
(ADR 0003) — so it adds no new injection surface. It is part of `EventQuery.text`, validated at request-parse time
(invalid text ⇒ 422) and stored verbatim in saved queries/history. `OR` between field expressions is rejected explicitly
(use `field:(a|b)`) rather than silently mis-parsed. Filters gained `negate` so any operator can be inverted.
Sigma (Milestone 5) and the AI planner (Milestone 6) will compile to `EventQuery`, not to engine DSL.

**Timeline.** `investigations/timeline.py` is a pure function over events: sort, rebuild process lineage by matching
`(host, pid)` (+ process name, + time order, to resist PID reuse), collapse repeated same-key activity (≤5 min gaps), and
compute interval statistics (median, jitter %) for groups. Nothing is inferred beyond what fields support; "beacon-like"
wording is a UI observation derived from the measured jitter, not a classification.

**Hunt data model.** `hunts` (hypothesis, status, window, data-source scope), `saved_queries` (tenant library or hunt-scoped),
`query_history` (per user, capped at 200; doubles as the persisted run summary), `hunt_findings` (evidence snapshots survive
retention deletes; event ids are verified against the caller's tenant), `hunt_notes`. All carry `tenant_id` and are always
filtered by `principal.tid`; foreign ids return 404.

**Exports** are capped (5 000 rows), rate-limited, audited, and CSV cells that start with `= + - @ TAB CR` are prefixed with `'`
to defuse spreadsheet formula injection from attacker-controlled telemetry.
