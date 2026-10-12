# ADR 0018 — Every search also asks the whole SIEM

**Status:** accepted. Extends ADR 0012/0015.

**Problem.** The LogRhythm connector is deliberately narrow: it collects one host's logs (`hostname` filter) under a 30,000 logs/minute cap. An
indicator that appears anywhere else in the SIEM (here: AI Engine "C2: Blacklisted Egress Port" alarms naming `51.89.20.151`) was invisible to
analysts unless the IP had been validated as an IOC, because only IOC hunts searched the whole SIEM.

**Decision.** Every interactive search also queries LogRhythm live, for the indicators it contains.
* `POST /api/v1/events/siem-search` takes the same body as `/events/search`. `events/siem_search.py` extracts SIEM terms: filters on indicator
  fields (`network.src_ip|dst_ip`, `auth.source_ip`, `host.ip`, `network.dst_domain`, `dns.question`, `process.hash.*`, `file.hash.sha256`,
  `host.hostname`) and bare indicators in free text (IP, domain, hash, e-mail). `POST /events/siem-lookup` does one indicator (threat-map panel).
* It reuses the filters verified on the live API (ADR 0015; a new `hostname` kind), whole-token attribution (a loose vendor filter can never create
  a false hit) and the same idempotent import as IOC hunts (deterministic event ids, so collection and search never duplicate each other).
* The connector's own host restriction is **not** applied: that is the point. Remaining filters LogRhythm cannot express (process name, ports,
  users...) are applied locally to what comes back and are reported back as "can't be searched by …"; negations are never searched.
* Honest status: `ok | partial | error | not_applicable | unconfigured | disabled`, what was searched, counts of logs matched / newly imported /
  already present, and truncation. A search with nothing to look up never touches the SIEM.
* Limits: at most the last 14 days of the range, 50 values per kind, ~150 s budget, two concurrent whole-SIEM searches per process, 12
  requests/minute/user, audited (`event.siem_search`, `event.siem_lookup`). Per source switch: `siem_search: false` in the data source config.
* UI: a status card under the search box on **Events** (re-runs the local search once if logs were imported), on the **hunt workspace** ("Show in
  results" re-runs the query), and a section in the **threat-map investigation panel**. The global search navigates to Events, so it is covered.

**Why import rather than just display.** Cases, the event drawer, pivots, detections and the map all work on stored events. Importing matches (as IOC
hunts already do) makes the search results first-class, at the cost of the platform accumulating the matching logs over time (subject to retention).

**Not covered.** The AI agent's `search_events` tool and scheduled detections still read only the platform's own store (the agent searches many times
per run; a live SIEM call per query would be too slow). IOC hunts already search the whole SIEM. Queries with no indicator (for example
`process.name:cmd.exe`) cannot be answered by LogRhythm's filter API and are not sent.
