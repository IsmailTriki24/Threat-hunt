# Architecture

> Status: **Milestones 1 (foundation), 2 (hunting), 3 (investigation), 4 (threat intel + ATT&CK) 5 (detection engineering) and 6 (AI hunting) implemented.** Sections marked *(planned)* are designed for but not yet built.

## 1. Goals
A SOC/CERT threat-hunting and investigation platform that evolves from manual hunting → assisted → AI-assisted →
autonomous without a rewrite. The seams that make that possible: a tenant-aware **query model** (the only way to ask
the telemetry store questions), a **tool boundary** (typed, authorised, audited operations — the same ones humans
and, later, the AI planner use), and **connectors** (all integrations behind one interface).

## 2. System overview
```
 Browser ──► Next.js (3000) ──/api/* rewrite──► FastAPI (8000) ──► PostgreSQL  (identity, config, audit; later hunts/cases)
                                                 │    │         └─► Redis       (rate limits, worker heartbeat, job queue)
                                                 │    └──────────► OpenSearch  (telemetry: events-*, endpoint-*, network-*, authentication-*, dns-*)
                                       arq worker ┘ (retention, heartbeat; later enrichment, detections, AI jobs)
                                                 MinIO (object store for reports/evidence — provisioned, used from M3)
```

## 3. Backend layout (`backend/app`)
| Package | Responsibility |
|---|---|
| `core/` | settings (fail-closed secret validation), JSON logging with request context, DB engine/session (UoW per request), error model, rate limiting, security middleware, metrics, password/JWT primitives |
| `auth/` | RBAC (`rbac.py`: roles→permissions), `Principal` + `require(permission)` dependency, login/refresh/logout/switch-tenant |
| `tenants/`, `users/` | tenant lifecycle (platform admin), tenant membership & user management (tenant admin) |
| `audit/` | append-only audit trail (DB trigger rejects UPDATE/DELETE), written in its own transaction |
| `events/` | canonical schema, **field registry**, engine-neutral `EventQuery`, `SearchBackend` protocol + OpenSearch implementation, ingestion service, pivots, HTTP API |
| `hunts/` | hunts, hypotheses, saved queries, per-user history, findings (evidence snapshots), notes, CSV/JSON export |
| `investigations/` | telemetry-derived timeline (process lineage, collapsing, periodicity) |
| `cases/` | case lifecycle state machine, evidence snapshots, IOCs, case assets, journal, versioned reports |
| `assets/` | asset inventory, discovery from telemetry, telemetry-derived relationships |
| `datasources/` | persisted connector instances, encrypted secrets, ingest keys, pull collection |
| `audit/` | audit trail (write + read API) |
| `intel/` | tenant-private IOC entities, provider adapters, explainable scoring, STIX/TAXII, sightings |
| `mitre/` | ATT&CK reference data, evidence-backed suggestion rules, mappings, technique risk summaries |
| `connectors/` | `Connector` interface, registry, `canonical`, `generic_json`, `sysmon` |
| `workers/` | arq worker: heartbeat, per-tenant retention |
| `seed/` | deterministic synthetic telemetry (phishing → PowerShell → C2 → persistence → LSASS dump → lateral movement) |
| `api/` | `/health`, `/ready`, `/metrics`, router assembly |



## 4. Request lifecycle & authorisation
1. Middleware: body-size cap (streamed bodies counted), request id, security headers, metrics, structured access log.
2. `get_principal`: verify JWT → load user → **re-validate membership/tenant/role in PostgreSQL** → `Principal`.
3. `require(Permission.X)`: 403 (+ audit `authz.denied`) if the role lacks it; 400 if a tenant-scoped route has no tenant context.
4. Handlers receive `principal.tid`; services never read a tenant id from the request.

Roles (`SUPER_ADMIN`, `TENANT_ADMIN`, `SOC_ANALYST`, `THREAT_HUNTER`, `INCIDENT_RESPONDER`, `VIEWER`) map to permissions in one table
(`auth/rbac.py`). Today the analyst-type roles share read access; they diverge as hunts/cases/detections land.

## 5. Telemetry pipeline
`raw record → Connector.normalize → EventIn → Event.from_input(tenant_id from principal) → bulk create into <family>-YYYY.MM.DD`.
* Ingest is idempotent when the source provides a native id (deterministic `_id`, `op_type=create`, 409 ⇒ duplicate).
* Template: `dynamic: strict`, generated from the field registry, so mapping and query validation cannot drift.
* Search: `EventQuery` → `OpenSearchBackend.compile()` → `bool{filter:[tenant, time, bool{user clauses}]}`; see ADR 0003.
* Lifecycle: worker deletes per-tenant data past `tenant.retention_days`. Hot/warm/cold tiering *(planned)* attaches as ISM
  policies per index family; the abstraction point is `SearchBackend` + the worker job.

## 6. Roadmap & vertical slices
| Milestone | Scope | State |
|---|---|---|
| 1 Foundation | compose stack, auth, tenants, RBAC, migrations, health, canonical schema, ingest, search API, search UI, seed | **done** |
| 2 Hunting | hunts/hypotheses, hunt query language, saved queries, history, findings, notes, export, pivots, timeline from telemetry | **done** |
| 3 Investigation | cases, evidence, IOC extraction, assets, audit views, reports, DataSource entity, ingest keys, SSRF-safe pull connector, Zeek/Suricata/Wazuh/WinEvt connectors | **done** (MinIO file export deferred) |
| 4 Threat intel | IOC entities, enrichment adapters (MISP, ThreatFox/abuse.ch, OTX, VT…) with graceful degradation, scoring, ATT&CK | **done** |
| 5 Detection engineering | Sigma → query compiler, rule lifecycle/testing, hunt→detection, scheduled evaluation, alerts | **done** (ADR 0010) |
| 7 IOC hunting | recent-IOC database, admin validation, automatic multi-source hunt, auto-generated case and report, watch-list re-hunts | **done** (ADR 0013) |
| 6 AI hunting | provider abstraction, tool system, agent loop, evidence-validated conclusions, NL→query | **done** (ADR 0011) |

## 7. AI design constraints (implemented in `app/ai/`, ADR 0011)
The model never receives credentials or shell access. It can only call registered **tools** (`search_events`, `get_event`,
`lookup_ioc`, …) that: take Pydantic-typed input, execute as the *invoking user's* `Principal` (so tenant isolation and RBAC
apply unchanged), are rate- and size-limited, and write audit records. Model-generated queries are parsed into `EventQuery`
— the same validator as human queries — before execution. Event content, IOCs and model output are treated as untrusted data.

## 8. Decisions
See `docs/adr/`.
