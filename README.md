# Threat Hunting & Investigation Platform

Multi-tenant SOC/CERT platform: **hypothesis → hunt → query → evidence → investigation → enrichment → ATT&CK → detection → case**.
Milestones 1–6 plus the automatic IOC-hunting workflow are implemented. See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and `docs/adr/` for decisions.

| # | Milestone | What you get |
|---|---|---|
| 1 | Foundation | Auth (JWT + refresh), tenants, RBAC, audit trail, canonical event schema, ingestion, OpenSearch-backed search with aggregations, health/metrics, seed data |
| 2 | Hunting | Hunts and hypotheses, hunt query language, saved queries and history, findings and notes, CSV/JSON export, pivots, timeline with process lineage |
| 3 | Investigation | Cases and workflow, evidence, IOC extraction, assets, reports, data sources with ingest keys, connectors (Sysmon, Zeek, Suricata, Wazuh, Windows event log, generic REST/JSON) |
| 4 | Threat intelligence | IOC entities, provider adapters (ThreatFox, URLhaus, OTX, VirusTotal, MISP) that degrade gracefully, explainable scoring, STIX/TAXII, sightings, MITRE ATT&CK matrix and evidence-backed mapping |
| 5 | Detection engineering | Sigma and hunt-query rules compiled to one executable form, versioned rule lifecycle gated on passing unit tests, backtests, scheduled evaluation, alerts that escalate to cases, hunt → detection |
| 7 | IOC hunting | Recent-only IOC database from feeds (URLhaus, Feodo, ThreatFox, OTX, MISP, Trend Suspicious Objects, lists, STIX), admin validation, automatic multi-source hunt (ingested + Trend/LogRhythm upstream), auto-generated case with report/coverage/ATT&CK, watch-list re-hunts |
| 6 | AI hunting (optional) | LLM provider abstraction, read-only permission-checked tools, bounded agent loop, conclusions verified against the events actually retrieved, question → query translation |

## Quick start
```bash
git clone <repo> && cd Threat-hunt
./scripts/init-env.sh        # or: cp .env.example .env   (dev placeholders, rejected in production)
docker compose up -d --build
docker compose logs init     # shows the generated demo password if SEED_PASSWORD is empty
```
| Service | URL |
|---|---|
| UI | http://localhost:3000 |
| API + docs | http://localhost:8000/docs (`/health`, `/ready`, `/metrics`) |
| OpenSearch | http://localhost:9200 (dev: security plugin off, loopback only) |
| MinIO console | http://localhost:9001 |

`init` (one-shot) runs Alembic migrations, installs the OpenSearch index template, and — when `SEED_DEMO_DATA=true` — seeds two demo
tenants with synthetic telemetry (the *Acme Bank* tenant contains a phishing → PowerShell → C2 → persistence → LSASS-dump → lateral-movement chain).

Demo users (password = `SEED_PASSWORD`, or the one printed by `init`):
`superadmin@hunt.example`, `admin|analyst|hunter|responder|viewer@acme.example`, `admin|analyst@globex.example`.

Try the hunt workspace: create a hunt, run `process.parent.name:WINWORD.EXE process.name:powershell.exe`, add the event as a finding, then open *Timeline around this event*.
Other searches: search `powershell`, filter `process.parent.name = WINWORD.EXE`, or `network.dst_ip = 203.0.113.45`; open an event and pivot.
Log in as `analyst@globex.example` to confirm none of Acme's events are visible.

## Ingesting your own data
```bash
TOKEN=$(curl -s localhost:8000/api/v1/auth/login -H 'content-type: application/json' \
  -d '{"email":"admin@acme.example","password":"…"}' | jq -r .access_token)
curl -s localhost:8000/api/v1/events/ingest -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{
  "source_type":"generic_json",
  "config":{"source":"myapp","default_event_type":"authentication",
            "field_map":{"timestamp":"ts","user.name":"who","auth.source_ip":"ip","outcome":"result"}},
  "events":[{"ts":"2026-10-07T10:00:00Z","who":"dave","ip":"10.1.1.9","result":"failure"}]}'
```
Connectors today: `canonical`, `generic_json`, `generic_rest` (pull), `sysmon`, `zeek`, `suricata`, `wazuh`, `windows_eventlog`, `logrhythm` (pull), `trend_vision_one` (pull).
For production-style ingestion create a *Data Source* (UI or `POST /api/v1/data-sources`) and send events to `POST /api/v1/ingest/{id}` with its one-time `hk_…` key. Add one by implementing `app/connectors/base.py:Connector` and registering it.

## Development
```bash
make infra                                   # datastores only
cd backend && python3.13 -m venv .venv && .venv/bin/pip install -e '.[dev]'
make init                                    # migrate + template + seed against the dev datastores
cd backend && set -a && . ../.env && set +a && DATABASE_URL=… uvicorn app.main:app --reload   # see Makefile for URLs
make check                                   # ruff, mypy --strict, bandit, pip-audit, pytest; frontend lint/typecheck/test/build
```
Backend tests run against real PostgreSQL (database `hunt_test`, recreated per run), Redis (db 15) and OpenSearch
(`test-*` indices removed afterwards) — start `make infra` first. New migration: `alembic revision --autogenerate -m "…"` from `backend/`.

## Layout
`backend/` FastAPI app, Alembic migrations, tests · `frontend/` Next.js + Tailwind + TanStack Query · `docs/adr/` decisions ·
`SECURITY.md` controls & known gaps · `CONTRIBUTING.md`.

## Threat intelligence
Lookups work with **no API keys** (local heuristics + your own watch-list). Add ThreatFox/URLhaus (abuse.ch Auth-Key), OTX, VirusTotal or MISP credentials under *Threat Intelligence → Providers* (tenant admin). Import STIX bundles or pull a TAXII 2.1 collection into the watch-list. Load the full ATT&CK matrix with `python -m app.cli mitre-load --file enterprise-attack.json` (the curated subset loads on `init`).

## SIEM / XDR sources (LogRhythm, Trend Vision One)
Both are pull connectors collected by the worker every 5 minutes. Create them under *Data Sources*, then use **Set credential** to add the
token / API key (write-only, stored encrypted). Trend Vision One: pick a `region` and one `dataset` per source (`alerts`, `oat`, `detections`,
`endpoint_activity`, `identity_activity`, `email_activity`, `mobile_activity`, `network_activity`, `cloud_activity`, `container_activity`, `audit_logs`, `response_tasks`); `oat` and `endpoint_activity` can be very high volume (a mid-size tenant produced ~50 endpoint events/s, several GB/day), so use the `filter` / `query` options to ingest only what you hunt on.
LogRhythm: set `base_url` (the :8501 gateway). Private hosts must be allow-listed on the server: `OUTBOUND_ALLOWED_NETWORKS=10.0.0.5/32` and add the
port to `OUTBOUND_ALLOWED_PORTS`. TLS is verified; for a self-signed appliance paste its certificate into `ca_pem` and set `tls_server_name` to a name in it.

## IOC hunting (automatic)
*IOC Hunting* is the end-to-end threat-hunt workflow: **feeds → threat bulletins → validation → automatic hunt → case.** Indicators are grouped under the **threat** they belong to (malware family, actor, campaign); the *Threats* table lists them with their IOC / IOA / TTP counts, and opening one shows its bulletin (description, IOCs, behaviours, ATT&CK techniques). Validating the bulletin hunts all of it. For documented techniques and aliases load the full ATT&CK dataset once: `python -m app.cli mitre-load --file enterprise-attack.json` (download from the MITRE CTI repository).
1. Add feeds under *Feeds* (no-key starters: **URLhaus recent URLs**, **Feodo Tracker**; add your own **Trend Vision One Suspicious Object List** with the same API key as the Trend data source; ThreatFox / OTX / MISP with their keys). Only *recent* indicators are imported (default 14 days) and stale ones expire; private, benign and allow-listed values never enter the database.
2. In the *Threats* table (sorted by "already in your telemetry", severity, confidence) a **tenant admin** opens a bulletin and validates it (individual IOCs and behaviours can be excluded). *All indicators* still lists the flat queue.
3. The worker hunts every source within about a minute: ingested telemetry, Trend Vision One upstream search (including datasets you do not ingest), and the whole LogRhythm SIEM (built-in, verified filters per indicator type; no setup beyond the data source; `ioc_search`, `ioc_search_max`, `ioc_batch` and `url_pattern_max` tune it; `ioc_filter_templates` can override a type). See ADR 0015.
4. A **case is opened automatically whether or not anything is found**: hunt report, per-source coverage, evidence, assets, ATT&CK mappings, severity and recommendations. No match with full coverage closes it; incomplete coverage keeps it open. Validated indicators are re-hunted every few hours and reopen the case on new activity.

## Detection engineering
*Detections* holds Sigma and hunt-query rules. A new rule is a DRAFT; it needs at least one must-match test case and a passing test run for its
current version before it can go ACTIVE (activating needs the `detections:manage` permission). Rules the engine cannot run exactly (regex,
aggregations, unmapped fields) are stored but never deployable. A worker evaluates ACTIVE rules every 5 minutes against newly ingested events and
raises alerts (one per rule and event); an alert can be acknowledged, closed or opened as a case. *Promote to detection* in a hunt turns its query into a DRAFT rule. Use *Backtest* to count matches over past telemetry without alerting.

## AI hunting (optional)
Off by default. Enable it in `.env`:
```bash
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=…          # stays on the server; never stored in the DB or sent to the browser
AI_MODEL=claude-sonnet-5-5   # default
```
The assistant can only run read-only searches as the signed-in user, inside their tenant. Every finding must cite events it actually
retrieved; unsupported findings are flagged and cannot be saved. Treat its output as a lead to verify, not a verdict. Runs are synchronous (up to
`AI_TIMEOUT_S`, default 120 s) and rate limited per user. The worker runs scheduled detections whether or not AI is enabled.

## Notes
* Requires ~1 GB free RAM for OpenSearch (heap set by `OPENSEARCH_JAVA_OPTS`). Dev compose disables OpenSearch disk watermarks.
* The MinIO image is Chainguard's build (`chainguard/minio`); the upstream `minio/minio` image is no longer published on Docker Hub.
