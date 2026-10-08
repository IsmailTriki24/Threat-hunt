# Threat Hunting & Investigation Platform

Multi-tenant SOC/CERT platform: **hypothesis → hunt → query → evidence → investigation → enrichment → ATT&CK → detection → case**.
All six milestones are implemented. See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and `docs/adr/` for decisions.

| # | Milestone | What you get |
|---|---|---|
| 1 | Foundation | Auth (JWT + refresh), tenants, RBAC, audit trail, canonical event schema, ingestion, OpenSearch-backed search with aggregations, health/metrics, seed data |
| 2 | Hunting | Hunts and hypotheses, hunt query language, saved queries and history, findings and notes, CSV/JSON export, pivots, timeline with process lineage |
| 3 | Investigation | Cases and workflow, evidence, IOC extraction, assets, reports, data sources with ingest keys, connectors (Sysmon, Zeek, Suricata, Wazuh, Windows event log, generic REST/JSON) |
| 4 | Threat intelligence | IOC entities, provider adapters (ThreatFox, URLhaus, OTX, VirusTotal, MISP) that degrade gracefully, explainable scoring, STIX/TAXII, sightings, MITRE ATT&CK matrix and evidence-backed mapping |
| 5 | Detection engineering | Sigma and hunt-query rules compiled to one executable form, versioned rule lifecycle gated on passing unit tests, backtests, scheduled evaluation, alerts that escalate to cases, hunt → detection |
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
Connectors today: `canonical`, `generic_json`, `generic_rest` (pull), `sysmon`, `zeek`, `suricata`, `wazuh`, `windows_eventlog`.
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
