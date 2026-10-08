# ADR 0015 — Searching LogRhythm for indicators

**Status:** accepted. Closes the LogRhythm gap left by ADR 0013 ("no ioc_filter_templates configured").

**Problem.** An IOC hunt searched LogRhythm only through events already ingested (one DC host), so cases with no match stayed open and the
SIEM's real history was never searched. LogRhythm's Search API needs numeric filter codes that the public docs omit, and a wrong filter either
fails after tens of seconds or silently matches nothing.

**Source of truth.** The gateway documents itself: `GET /lr-search-api/swagger-json` (the Redoc page links to it) contains the full
`FieldFilterTypeEnum` (119 codes), the value-type enum, the operator semantics (fieldOperator And=1/Or=2, filterMode In=1/Out=2, matchType
Value=0/SQLPattern=1/Regex=2) and the value-encoding rules. We read it with a credentialed GET; nothing is guessed against production.

**Verified on the live SIEM** (positive and negative controls, short windows first): `IP=17` with value type 5 and a *plain string* (a string-typed IP
fails after ~35 s; source IP 18 and destination IP 19 behave as named); several values inside one filter are OR'd; an Or group works and an And group
narrows; hostname exact and suffix patterns work and accept lists; hash (138), sender/recipient (31/32) lists of 50 values over 24 h finish in ~5 s;
**a group with more than one URL-pattern item fails**, while a single one works. A 7-day search carrying 25 indicators takes about a minute.

**Design (`connectors/logrhythm.py`, `iochunt/hunting.py`).** Built-in filters per kind (ip, domain, md5/sha1/sha256, email, url_pattern) — no template
needed; console-captured templates remain as a per-type override. Indicators are batched per kind (default 25 per search). A URL is searched through its
host (IP or hostname) in batches and accepted only if the full URL appears in the log; a small prioritised number (default 10) are also searched by exact
URL pattern, one search each, to catch logs that record only the URL. Each returned log is attributed by scanning the log itself (LogRhythm field names
vary by log source), with whole-token rules, so a loose filter can never create a false match; matched logs are imported as events so cases can cite
them. Per hunt: at most `ioc_search_max` (200) indicators, highest priority first (seen in our telemetry, then confidence), within a time budget; anything
not reached makes the coverage `truncated`, which keeps a no-match case open rather than overclaiming. Searches run against the whole SIEM, not the host the
source ingests from. `ioc_search: false` switches it off per source.

**Not verified / limits.** No hash, URL, e-mail or domain-in-URL data exists in the domain-controller logs, so those filters are *accepted and fast* but their
semantics are unproven until such a log source is onboarded; the controls for IPs and hostnames are real. Behaviour (IOA) searches in LogRhythm (process
and command-line filters) are not implemented: behaviours run against ingested LogRhythm events and Trend upstream.
