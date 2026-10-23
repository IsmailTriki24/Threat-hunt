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

## Design system
The UI is a light, enterprise-grade theme (purple identity `#7568E9`) built on tokens and a small shared kit; see **docs/design-system.md** for tokens, components, conventions and the accessibility rules, and ADR 0017 for the decision.

## Layout
`backend/` FastAPI app, Alembic migrations, tests · `frontend/` Next.js + Tailwind + TanStack Query · `docs/adr/` decisions ·
`SECURITY.md` controls & known gaps · `CONTRIBUTING.md`.

## Threat intelligence
Lookups work with **no API keys** (local heuristics + your own watch-list). Add ThreatFox/URLhaus (abuse.ch Auth-Key), OTX, VirusTotal or MISP credentials under *Threat Intelligence → Providers* (tenant admin). Import STIX bundles or pull a TAXII 2.1 collection into the watch-list. Load the full ATT&CK matrix with `python -m app.cli mitre-load --file enterprise-attack.json` (the curated subset loads on `init`).

## Access model (tenants and roles)
A **platform administrator** (`SUPER_ADMIN`) sees every tenant, creates tenants and their **tenant admin**, manages members, and assigns each tenant's
log sources; tenant users never configure or see source credentials. Production bootstrap, no demo data needed:
```
python -m app.cli create-superadmin ops@example.com                    # prompts for a password
python -m app.cli create-tenant wifak-bank "Wifak Bank" admin@wifak.example   # prompts for the admin password
```
Then sign in as the platform administrator, open the tenant and add its LogRhythm and Trend Vision One sources. See ADR 0026.

## SIEM / XDR sources (LogRhythm, Trend Vision One)
Both are pull connectors collected by the worker every 5 minutes. The **platform administrator** attaches them to a tenant (*Tenants → Open*, then *Data Sources*; tenant users see them read-only), then use **Set credential** to add the
token / API key (write-only, stored encrypted). Trend Vision One: pick a `region` and one `dataset` per source (`alerts`, `oat`, `detections`,
`endpoint_activity`, `identity_activity`, `email_activity`, `mobile_activity`, `network_activity`, `cloud_activity`, `container_activity`, `audit_logs`, `response_tasks`); `oat` and `endpoint_activity` can be very high volume (a mid-size tenant produced ~50 endpoint events/s, several GB/day), so use the `filter` / `query` options to ingest only what you hunt on.
**Whole-SIEM search:** the connector collects only what its `hostname`/`query_filter` selects, but every search in *Events*, the hunt workspace and the threat map also asks the **whole** LogRhythm SIEM live for the indicators in it (IP, domain, hash, e-mail, host name) and imports the matching logs, so nothing stays invisible because of the collection scope (ADR 0018; switch off with `siem_search: false`). LogRhythm: set `base_url` (the :8501 gateway). Private hosts must be allow-listed on the server: `OUTBOUND_ALLOWED_NETWORKS=10.0.0.5/32` and add the
port to `OUTBOUND_ALLOWED_PORTS`. TLS is verified; for a self-signed appliance paste its certificate into `ca_pem` and set `tls_server_name` to a name in it.

## IOC hunting (automatic)
*IOC Hunting* is the end-to-end threat-hunt workflow: **feeds → threat bulletins → validation → automatic hunt → case.** Indicators are grouped under the **threat** they belong to (malware family, actor, campaign); the *Threats* table lists them with their IOC / IOA / TTP counts, and opening one shows its bulletin (description, IOCs, behaviours, ATT&CK techniques). Validating the bulletin hunts all of it. For documented techniques and aliases load the full ATT&CK dataset once: `python -m app.cli mitre-load --file enterprise-attack.json` (download from the MITRE CTI repository).
1. Add feeds under *Feeds* (no-key starters: **URLhaus recent URLs**, **Feodo Tracker**; add your own **Trend Vision One Suspicious Object List** with the same API key as the Trend data source; ThreatFox / OTX / MISP / OpenCTI with their keys). Only *recent* indicators are imported (default 14 days) and stale ones expire; private, benign and allow-listed values never enter the database.
2. In the *Threats* table (sorted by "already in your telemetry", severity, confidence) a **tenant admin** opens a bulletin and validates it (individual IOCs and behaviours can be excluded). *All indicators* still lists the flat queue.
3. The worker hunts every source within about a minute: ingested telemetry, Trend Vision One upstream search (including datasets you do not ingest), and the whole LogRhythm SIEM (built-in, verified filters per indicator type; no setup beyond the data source; `ioc_search`, `ioc_search_max`, `ioc_batch` and `url_pattern_max` tune it; `ioc_filter_templates` can override a type). See ADR 0015.
4. A **case is opened automatically whether or not anything is found**: hunt report, per-source coverage, evidence, assets, ATT&CK mappings, severity and recommendations. No match with full coverage closes it; incomplete coverage keeps it open. Validated indicators are re-hunted every few hours and reopen the case on new activity.

## Global threat map
*Threat Map* (`/threat-map`) separates three questions on one MapLibre world map: **Global threat intelligence** (IP indicators your feeds report; reported, not
confirmed against you), **Observed network activity** (addresses in your own telemetry; arcs only for source→destination pairs the events establish) and
**Correlated threats** (observed addresses that are also reported intelligence, plus events an IOC hunt matched). Everything is aggregated server-side from
real data and filtered by time range, layer, country/region, IOC type, severity, confidence, category, feed, telemetry source, internal/external and a
search (IP, CIDR, `AS15169`, country, text). Click a marker for the investigation panel and the existing hunt, case and intelligence actions. Empty layers say
which integration is missing; nothing is simulated. Locations are GeoIP estimates, never an attacker's location. See ADR 0016.
* **GeoIP (local, no keys):** `scripts/fetch-geoip.sh` downloads DB-IP Lite City + ASN (CC BY 4.0) into `./data/geoip` (git-ignored, mounted read-only into the backend); or place
  `GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb` there and set `GEOIP_DB_PATH` / `GEOIP_ASN_DB_PATH`. `GEOIP_PROVIDER=none` disables locations. Restart the backend after changing databases.
* **Set `THREATMAP_OWN_NETWORKS`** (comma-separated CIDRs of your own public space) or your own addresses appear as the busiest remote "country". Optionally set
  `THREATMAP_HOME_LAT` / `THREATMAP_HOME_LON` / `THREATMAP_HOME_LABEL` so inbound/outbound arcs have a far end; `THREATMAP_MAX_MARKERS` caps markers per request.
* **Needs:** an IOC feed (*IOC Hunting → Feeds*: MISP, OpenCTI, OTX, ThreatFox, URLhaus, Feodo, Trend, STIX, text) for the intelligence layer; a source filling `network.src_ip` / `network.dst_ip` /
  `auth.source_ip` (firewall, IDS/IPS, EDR network, SIEM, identity sign-ins) for observed activity; both for correlation.
* **API** (all GET, tenant-scoped, `intel:read` + `events:read`): `/api/v1/threat-map/status`, `/data` (cards, countries, markers, rankings, timeline), `/flows`, `/correlations` (paginated), `/indicator?ip=`.
  Shared query parameters: `layer`, `range` (`1h|24h|7d|30d|custom` + `start`/`end`), `country`, `continent`, `ioc_type`, `severity`, `min_confidence`, `category`, `source` (feed), `log_source`, `scope`, `q`.
* **Test:** `cd backend && pytest tests/test_threatmap_geo.py tests/test_threatmap_api.py tests/test_opencti_feed.py` (needs the compose Postgres/Redis/OpenSearch) · `cd frontend && npx vitest run src/__tests__/threat-map`.

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
