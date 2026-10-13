# ADR 0023 — Events becomes "SIEM Search": the SIEMs are searched live, nothing is copied

**Status:** accepted. Supersedes the stored-events role of the Events page (ADR 0018 keeps its hunt-workspace and threat-map lookups).

**Problem.** With collection off (ADR 0019-0022) the Events page searched a shrinking, stale copy of the SIEMs' logs.

**Decision.** `/events` is now **SIEM Search**. A query goes straight to LogRhythm and to the Trend Vision One datasets that have a query surface
(`POST /events/siem-query`); results are shown from the SIEMs and nothing is stored.
* **Query.** The same free text / `field:value` language / filters / time range as everywhere else (window capped at 14 days). `a b` both, `"a b"` phrase,
  `-a` / `NOT a` without, `x OR y` alternatives.
* **LogRhythm** is asked with the filters verified on production (ADR 0020/0021): indicators (IP, domain, hash, e-mail, host) in batches; otherwise the
  query's positive filters compiled to AND-ed searches (process, command line, user, host, IPs, hash); otherwise a bare word is looked for in process,
  command line, user, host and URL (five searches, one URL pattern each). **Trend** gets TMV1 queries for indicators, mapped filters and words
  (endpoint activity, detections, identity), with the existing clause-by-clause fallback for fields a dataset does not know.
* **Every returned record is checked locally against the whole query** (filters, `where`, and the words, with indicators as whole tokens), so a loose
  vendor search can never show a false hit. What a source cannot be asked is listed per source.
* **Nothing is stored until an event is opened.** The result (up to 500 events) is held in Redis for 30 minutes under a `search_id`;
  `POST /events/siem-import` stores just the chosen events (idempotent, same deterministic ids), after which the normal event drawer, pivots and
  add-to-case work. A held result of another tenant is not importable. Searches are audited (`event.siem_query`) and rate-limited (12 per minute).
* **UI.** One merged table (client-side sort and paging over the held result), a status line per source (read / matched / ms / failure / what it could not
  be asked), a source picker kept in the URL, counts in the side panel computed from the results. An empty query asks the SIEMs nothing.

**Not changed.** Hunts, the AI agent, timelines and scheduled detections still read the platform's own store (the ~2 million events collected before
collection was switched off, until retention removes them, plus swept matches and opened events). They do not see the SIEMs live.

**Limits.** Reading is capped per search (1,500 logs / events) and the result at 500 events, flagged as truncated. A LogRhythm search over a long window
with a broad term can take up to a minute. Percent-encoded needles cannot be searched in LogRhythm (ADR 0021). Trend datasets other than endpoint
activity, detections and identity are not offered.
