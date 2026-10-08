# Threat Hunting & Investigation Platform

Multi-tenant SOC/CERT platform: **hypothesis → hunt → query → evidence → investigation → enrichment → ATT&CK → detection → case**.
Milestones 1–5 are implemented (foundation, hunting, investigation, threat intelligence + MITRE ATT&CK, detection engineering): auth, tenants, RBAC, canonical event model, ingestion, OpenSearch-backed
event search with aggregations, event investigation (pivots, raw view), audit trail, health/metrics, seed data, tests.
See [ARCHITECTURE.md](ARCHITECTURE.md) for the roadmap (AI hunting is *not built yet*).

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

## Notes
* Requires ~1 GB free RAM for OpenSearch (heap set by `OPENSEARCH_JAVA_OPTS`). Dev compose disables OpenSearch disk watermarks.
* The MinIO image is Chainguard's build (`chainguard/minio`); the upstream `minio/minio` image is no longer published on Docker Hub.
