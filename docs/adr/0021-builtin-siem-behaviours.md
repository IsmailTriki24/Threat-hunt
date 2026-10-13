# ADR 0021 — Built-in SIEM behaviours raise alerts from inside LogRhythm

**Status:** accepted. Extends ADR 0019/0020.

**Problem.** Behaviours (ADR 0020) only existed as part of a threat bulletin. Attacks that need no bulletin (password spraying, a WebLogic exploit
request, a privileged group change) were invisible once the platform stopped copying the SIEM's logs.

**Decision.** A catalogue of built-in behaviours (`iochunt/siem_behaviours.py`) is swept inside LogRhythm with the same exact-progress queue as indicators
(`sb:<key>` entries, per-source `siem_behaviours` / `siem_behaviours_disabled`). A detection is an **Alert** of a platform-managed detection rule
(`format = "siem"`, hidden from the format list, skipped by the stored-event evaluator, tagged `siem-builtin`, created on first use per tenant), so alerts
live on the Detections page and can be escalated to a case like any other. Alerts are unique per (rule, event); an overlapping window never duplicates.
The first event of a burst is the alert's event; it and up to five samples are imported so the alert can be opened. Nothing else is stored.

**Catalogue (v1).** Chosen from what this SIEM holds (WebLogic access logs, Windows authentication events from the DCs, Cisco Firepower / ISE):
* *Password spraying* (T1110.003, HIGH): at least 30 failed sign-ins (4625 / 4771 / 4776) against at least 12 different accounts from one source in 10 minutes.
* *Brute force against one account* (T1110.001, MEDIUM): at least 40 failures of one account from one source in 10 minutes.
* *Account lockout burst* (T1110, MEDIUM): 3 or more accounts locked out (4740) in 10 minutes.
* *Security-relevant account or audit change* (HIGH / MEDIUM): 4720, 4724, 4728, 4732, 4756, 4719, 1102, 104, one alert each.
* *Web attacks* (T1190): path traversal, sensitive-file access, WEB-INF access, WebLogic wls-wsat / `_async` / `bea_wls_` / console traversal exploit
  paths, JNDI injection, script injection, SQL injection, command execution.

**Calibration (production, 60-minute sample of 1,735 failed sign-ins).** Computer accounts (`name$`) produced 1,429 of them (one server alone 1,304), so they
are ignored. For human accounts the normal peak in any 10 minutes was 19 failures and 8 accounts from one source and 19 failures for one account; the
thresholds sit well above that. No attack pattern matched anything in the hour (no false positives); account / group-change events were absent from
the last 24 hours (see below).

**Verified on production.** One search per URL pattern (several values in one URL filter make LogRhythm fail, again confirmed); `?`, `=`, `&`, `;` in
patterns match literally; `_` is a single-character wildcard and `%` any run (so every search is a superset and the regex on the decoded URL decides);
VendorMsgID lists are OR. Not provable here (no such traffic): the attack characters `<`, `$`, `{` and the encoded forms.

**Limits.**
* In the WebLogic logs `originIp` is a single front-end address, so web alerts name the target host and URL, not the real client.
* Percent-encoded forms are re-checked locally but cannot be searched: `%` inside an SQL pattern is the wildcard, so an encoded needle would match nearly
  everything. If the gateway logs the decoded URL they are found; if it logs the raw URL only the literal forms are.
* The DC logs held in LogRhythm contain only authentication failures (every sampled log has class "Authentication Failure"). Account, group and audit
  change rules therefore stay dormant here (one cheap search per window) until the DCs forward those events.
* A scanner producing thousands of matching requests yields at most 50 alerts per behaviour and window; the rest is counted in the sweep status.
* Aggregates are evaluated per sweep window plus a 10-minute look-back; a very slow burst split across the thresholds is not detected.

**Batch size.** Indicator searches are now batched at 100 per kind instead of 25. Controls on production: 100 IPs, 100 domains (200 patterns) and 100 sha256
(200 values) each completed in about 6 seconds, the same as 25, and a known-present IP / hostname hidden among 99 unrelated values returned exactly the
same logs as when searched alone (170 and 328 logs). This cuts the searches of a 1,238-indicator pass by about 4x; the cost of a search is its fixed overhead, not its size.
