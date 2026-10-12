# ADR 0016 — Global threat map

**Status:** accepted.

**Problem.** Analysts had no geographic view that separates *what third parties report* from *what our own sensors saw*, and nothing
joined the two. A map is easy to make misleading in a SOC: GeoIP is an estimate, a feed's IOC is not an attack, and invented activity is worse
than no map. The requirement is a map that is an investigation tool (marker → context → existing workflow), not a picture.

**Decision.** One read-only API (`/api/v1/threat-map`) and one page (`/threat-map`) built on existing stores. No new tables, no parallel IOC
store, no duplicated workflows; the only schema change is two composite indexes (migration 0012).

## Three layers, three different questions
| Layer | Source | Meaning |
|---|---|---|
| Global threat intelligence | `iocs` (type `ip`, not REJECTED, `last_seen` in range) + analyst look-ups in `intel_entities` rated malicious/suspicious | *Reported* by a third party. Never "an attack on us". |
| Observed network activity | OpenSearch: `network.src_ip`, `network.dst_ip`, `auth.source_ip` | *We saw* this address. Says nothing about reputation. |
| Correlated threats | (a) observed address ∩ reported IP (live), (b) events an earlier IOC hunt matched (`ioc_matches`, **any** indicator type) whose event also names a public address | Observed activity that matches intelligence or a detection. |

A layer with no backing data is empty, and `/status` states what is missing ("add an IOC feed", "connect a firewall/IDS/EDR/SIEM source").
There is no demo or synthetic mode.

## Geolocation
`app/threatmap/geo.py`. `classify_ip` first: only **public** (globally routable) addresses are ever looked up. Private (RFC 1918/ULA), loopback,
link-local, CGNAT, multicast, documentation/reserved ranges and IPv4-mapped forms get a *class*, never a location. (Python's `is_private` also
covers documentation ranges; the classifier decides private explicitly so TEST-NET addresses are "reserved", not "internal".)
The provider is configurable (`GEOIP_PROVIDER=mmdb|none`). `mmdb` reads any MaxMind-format database locally (GeoLite2 or DB-IP Lite), so no address
leaves the platform and nothing external is called while rendering. Lookups (including misses) are memoised per process. Without a database the map
says so and nothing is placed. `THREATMAP_OWN_NETWORKS` lets an operator declare their own public ranges, which are then treated as "ours" rather than
as remote endpoints; without it a bank's own public space looks like the busiest "country".

Locations are presented as approximate everywhere (map footer, panel, `geo_note`). A reported/estimated location of an *address* is never
described as an actor's location.

## Arcs
Drawn only from pairs the event itself establishes (`network.src_ip` and `network.dst_ip` both present). Inbound/outbound/internal/external is
derived from the two addresses' classes. A public↔private pair has no far end on a map unless the operator configures the organisation's location
(`THREATMAP_HOME_LAT/LON`); until then those pairs are not drawn and the UI says why. Internal↔internal pairs are excluded server-side.

## Backend
`app/threatmap/` — `geo.py` (classification, providers), `telemetry.py` (OpenSearch aggregations: per-IP activity, composite flow pairs, histogram,
per-IP events), `service.py` (filters, intel loading, hunt correlation, record building, cards), `router.py`.
* Aggregation happens in the backend: the browser receives per-IP summaries (max `THREATMAP_MAX_MARKERS`, default 1,500, flagged `truncated`) and
  country rows, never raw events. Terms aggregations are bounded (3,000 per field) and the response says when that bound was reached.
* Tenant isolation: every query is scoped by `principal.tid`; there is no tenant parameter. Needs `intel:read` **and** `events:read`.
* Filters are validated once (`FilterParams`) and shared by every route so the map, cards and panels always agree: time range (1h/24h/7d/30d/custom,
  max 90 days), layer, country, continent, IOC type, severity, confidence, category/malware/threat, feed (`source`), telemetry source (`log_source`),
  scope (any/external/internal), and a search that is classified before use (IP, CIDR, `AS15169`, country code/name, otherwise text).
* Cards are computed independently of the layer on screen, from the same filters (`unique_malicious_ips`, `countries_with_indicators`,
  `observed_events`, `correlated_threats`, `high_severity_detections` = detection-rule alerts rated high/critical in range).
* Degradation: if telemetry search is down, the intelligence layer still renders with `partial: ["telemetry"]` and null telemetry-derived cards; the
  observed/correlated layers return 503.
* Reads of the indicator panel are audited (`threatmap.indicator.view`). Per-user rate limits apply to each route.
* Feed text (names, descriptions, tags) is returned verbatim as JSON strings and rendered as text by the UI; references are only forwarded when
  they are http(s) URLs.
* Real-time: the page polls every 30 s (pausable). There is no streaming endpoint for telemetry today; polling reuses the same bounded queries.

## Frontend
MapLibre GL JS, with an **offline style**: country boundaries are `public/geo/countries.geojson` (Natural Earth, public domain) and the style
has no tiles and no font glyphs. This keeps the strict same-origin CSP (only `worker-src blob:` was added, for MapLibre's worker) and means a SOC
console does not tell a tile provider which regions an analyst is inspecting. Consequences: cluster counts are DOM labels, there are no
place-name labels, and the country shade is a data-driven `match` on ISO code. The map is created once; later changes only call `setData` /
`setPaintProperty`, handlers are registered once and read callbacks through a ref, and the map is removed on unmount (tested). Arc animation is a
dash-offset cycle, off by default and disabled under `prefers-reduced-motion`.
Marker → investigation panel (location, intelligence with provenance, own telemetry, matched events, hunt matches, related IOCs, peers, alerts,
cases). Actions reuse existing, separately authorised endpoints and are only offered when the server says the caller may: copy/defang, investigate
(`/events` with a hunt-language query), launch hunt (`POST /ioc/iocs/validate`, tenant admin), add to IOC queue (`POST /ioc/iocs`), open intelligence
record, add events to a case.

## Threat-intelligence adapters
Feeds are the existing `iochunt/feeds` interface (normalise → shared guard-rails → `iocs`, provenance and confidence kept). MISP, OTX, ThreatFox,
URLhaus, Feodo, Trend Suspicious Objects, STIX and text lists already existed; this change adds **OpenCTI** (GraphQL, single-observable STIX
patterns, `x_opencti_score`/`confidence`, revoked excluded, paged and capped). **Not verified against a live OpenCTI instance**; it is tested
against the documented schema with a mocked transport. Feed failures are recorded on the feed and stale data is flagged (`stale`), not hidden.

## Not done / limits
* No live OpenCTI/MISP instance was available to verify against.
* Only IP indicators have a location; domains, URLs and hashes appear on the map only through a correlated event that names a public address.
* DB-IP Lite and GeoLite2 are city-level estimates; accuracy varies and is often poor for mobile, VPN and hosting addresses.
* Observed telemetry needs sources that populate `network.*` or `auth.source_ip` (firewall, IDS/IPS, EDR network, SIEM, identity sign-ins).
* Marker aggregation is capped per request (3,000 per IP field); very large tenants should narrow the range or filters.
