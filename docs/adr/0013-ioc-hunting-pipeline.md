# ADR 0013 — Automatic IOC hunting pipeline

**Status:** accepted

**Shape.** Modelled on TaHiTI (Initiate → Hunt → Finalize, intelligence feeding every step) and on the indicator-match practice of Sentinel,
Elastic and MISP: **collect → triage → hunt → report → keep watching.**

1. **Collect (`iochunt/feeds`, `ingest.py`).** Per-tenant feeds on a schedule: URLhaus CSV and Feodo (no key), ThreatFox, OTX, MISP, Trend
   Vision One Suspicious Object List, plain-text lists and STIX bundles. A feed only returns raw indicators; shared code normalises
   (refangs, types, validates) and applies guard-rails before anything is stored: **only recent** (per-feed age limit, default 14 days, judged
   by last sighting), not already past `valid_until`, confidence floor, per-run item cap (newest/highest-confidence kept), and false-positive
   guards in the spirit of MISP warning-lists / RFC 9424 (private and loopback addresses, public resolvers, big benign domains, empty-file
   hashes, plus the tenant allow-list, which also covers subdomains and URLs on an allowed domain). Upserts are idempotent; a validated or
   rejected decision is never overwritten by a feed refresh. Unreviewed indicators expire when they age out; validated ones are watched for 30 days.
2. **Prescreen.** New indicators are checked against the tenant's own telemetry in cheap batched `in` queries. "Already seen in your
   environment" sorts to the top of the triage queue: a published indicator that has *already appeared* in the estate is worth far more than one that merely exists.
3. **Triage.** Only a tenant admin can validate (`iochunt:validate`) or manage feeds (`iochunt:manage`); analysts and hunters read. Validation
   marks the indicators VALIDATED and queues one hunt with a generated hypothesis, atomically and audited.
4. **Hunt (`hunting.py`).** The worker claims the hunt (atomic PENDING→RUNNING; a dead worker's hunt is requeued) and searches every source:
   the local index (everything ingested), Trend Vision One *upstream* (vendor retention, including datasets we deliberately do not ingest for
   capacity — verified syntax `field:"value" OR …`, quoted wildcards for command lines, clause-by-clause fallback on "Unsupported query field"),
   and LogRhythm upstream through console-captured per-type filter templates (its filter codes are not public, so we never guess against a
   production SIEM; without templates only ingested LogRhythm events are covered and the report says so). **Every candidate event is
   re-attributed** to the exact indicator it contains with whole-token rules (a domain matches as a host suffix, never inside a longer name; URLs
   need the full URL, so a shared host cannot create false matches). Matched upstream events are indexed so cases can cite them.
5. **Report (`casebuild.py`).** Always a case, match or not: a platform Hunt with findings, a Markdown hunt report (verdict, hypothesis,
   indicator table, **per-source coverage**, findings, affected assets, ATT&CK, recommendations), evidence, CaseIoc rows, assets, and ATT&CK
   mappings — LOW when only declared by the feed, MEDIUM when an event evidences the indicator, plus the existing evidence-backed suggester.
   Severity comes from indicator confidence, role (C2/ransomware), host count and volume. **No match and full coverage ⇒ the case is closed
   with the coverage as its resolution. No match but a source errored/was skipped/truncated ⇒ it stays open and says the verdict is not conclusive.**
   Total failure ⇒ the hunt is FAILED and retryable, with no misleading case.
6. **Keep watching.** Validated indicators are re-hunted every 6 hours over the new window only; a new match is appended to the same case
   (evidence, activity note, severity raised) and a closed case is reopened. Matches are unique per (indicator, event), so nothing is reported twice.

**Honest limits.** Coverage is only as good as the sources: Trend alerts/OAT/audit feeds have no IOC query surface (their ingested events are
covered locally); LogRhythm upstream search needs captured templates; free feeds are noisy (URLhaus carries ~30k URLs/week — hence the cap, the
confidence score and the prescreen); ThreatFox/OTX/MISP need the operator's own keys. ATT&CK for IOC-only context is inferred from the indicator's
role and is deliberately low confidence.
