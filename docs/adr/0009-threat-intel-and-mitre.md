# ADR 0009 — Threat intelligence enrichment and MITRE ATT&CK mapping

**Status:** accepted

## Threat intelligence
* **Entities are tenant-private.** `intel_entities` / `intel_observations` / `intel_relations` all carry `tenant_id`. A provider answer may have been
  obtained with one tenant's credentials and an analyst verdict is that tenant's judgement, so nothing is shared across tenants (not even cached
  reputation). Cross-tenant relations are impossible: both ends are looked up under the caller's tenant.
* **Adapters, not dependencies.** `intel/providers/*` implement one `Provider` contract. Offline providers (`heuristics`, `watchlist`) are always
  available, so lookups work with zero API keys. Paid/keyed providers (ThreatFox, URLhaus, OTX, VirusTotal, MISP) are disabled until a tenant admin
  stores credentials (Fernet-encrypted, write-only). Unconfigured providers are reported as *skipped* with a reason, failing providers as
  *error* observations; neither fails the request.
* **Remote data is untrusted.** All HTTP goes through `core/ssrf.py`; MISP's operator-supplied URL is validated per request. Providers extract
  allow-listed fields, clip lengths and cap stored JSON (8 KiB); content is stored and rendered as text only and never drives behaviour.
* **Scoring** (`intel/scoring.py`) is a weighted noisy-OR with benign dampening; the score is accompanied by a per-signal breakdown and coverage.
  "unknown" is a first-class verdict — absence of reports is not evidence of safety. Analyst/feed verdicts enter as the `watchlist` signal, and a
  feed import never overwrites an analyst's decision.
* **STIX/TAXII.** Only simple single-observable indicator patterns are imported (compound `AND` patterns are skipped), expired indicators are
  dropped, size limits apply. TAXII 2.1 pull is manual (admin-triggered) in this milestone.
* **Sightings** are computed live against the tenant's telemetry (not stored), so they are always current and tenant-scoped.

## MITRE ATT&CK
* Reference data (tactics/techniques) is global and read-only; a curated built-in subset ships in `mitre/data.py` and the full matrix can be loaded
  from an official STIX bundle with `python -m app.cli mitre-load --file enterprise-attack.json`.
* **A mapping is a claim with reasoning.** `mitre_mappings` requires reasoning (≥10 chars); MEDIUM/HIGH confidence requires ≥1 evidence event that
  resolves inside the tenant. Mapping a case/hunt additionally requires that object's write permission; closed cases are locked.
* **Suggestions are deterministic rules** (`mitre/suggest.py`) that cite the exact fields/values matched and never fire without an evidence event.
  Where a stage is inferred rather than observed (e.g. phishing from an Office → PowerShell chain) the reasoning says so and confidence is capped.
* **Risk** per technique: HIGH needs a HIGH-confidence mapping plus (≥2 hosts, ≥10 events, or a HIGH/CRITICAL asset); MEDIUM for any MEDIUM/HIGH
  mapping; else LOW. The inputs are reported with the result (`risk_reasons`).
