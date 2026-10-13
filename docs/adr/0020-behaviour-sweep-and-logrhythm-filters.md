# ADR 0020 — Behaviours are searched inside the SIEMs, with verified LogRhythm filters

**Status:** accepted. Extends ADR 0015/0018/0019. Collection of the LogRhythm DC and of the heavy Trend datasets is switched off in favour of this.

**Problem.** The sweep (ADR 0019) looked only for known indicators. A threat is also what an attacker *does* (a behaviour, IOA), and behaviours could only be
hunted in events the platform had already copied in. Without collection there would be nothing to hunt.

**Source of truth.** The gateway's own `GET /lr-search-api/swagger-json` (LogRhythm 7.9) lists 119 `FieldFilterTypeEnum` codes, value types
(Int32 = 2, String = 4, IPAddress = 5, ...), match types (Value 0 / SQLPattern 1 / Regex 2) and the returned field names. Nothing below was guessed
against production.

**Controls run on the production SIEM** (read-only, 10-minute windows, capped results, one search at a time; positive = every returned log
carries the value, negative = a made-up value returns nothing). The `queryTimeout` must be 5 minutes: with 1 minute LogRhythm reports "Search Failed" even when it returns results.

| Verified (positive + negative) | Code | Notes |
|---|---|---|
| VendorMsgID (Windows event id) | 37 | string, exact; lists are OR |
| Login, Account | 29, 30 | string, case-insensitive |
| Process | 41 | string |
| Command | 112 | exact and SQL pattern `%x%` |
| Object | 34 | |
| Reason (pattern), Action, Policy | 149, 154, 139 | |
| URL (pattern) | 42 | one URL item per group (ADR 0015) |
| IP / SIP / DIP, HostName, Hash, Sender / Recipient | 17 / 18 / 19, 23, 138, 31 / 32 | ADR 0015 |
| MsgClass, CommonEvent | 10, 11 | **integers only** (Int32 with `classificationId` / `commonEventId`); by name the search fails |
| AND of items (narrows), OR inside an item, NOT (filterMode 2) | | `4625 AND Object=NtLmSsp` = 35, `4771 AND NtLmSsp` = 0 |

Accepted by the API but **not provable** here because this SIEM holds no such data (no endpoint process telemetry): ParentProcessName 146, UserAgent 144,
ThreatName 152, Message 35 (also with Regex). MPERule 12 and Domain 39 returned nothing for values taken from real logs, so their semantics are unknown.
None of these is used.

**What this SIEM contains** (2-minute sample of the whole SIEM): WebLogic access logs (url, HTTP verb in `command`), Windows Security events from
the DCs (authentication only), Cisco Firepower and ISE, banking-application logs. No Sysmon / 4688 process logs: process behaviours are visible in
Trend, not here. Windows `process`/`command` hold Kerberos values (`krbtgt`, `0x40810010`) on authentication events.

**Design.**
* `connectors/logrhythm.py: ioa_searches(Condition)` turns a behaviour's canonical condition into LogRhythm searches. Disjunctive normal form (at most 16
  branches), one search per branch, items AND-ed. Only verified filters are used (process name as a suffix pattern because LogRhythm may hold a full path,
  command line, user, host, source / destination IP, hash, event id). What it cannot express (parent process, negations, ports ...) is dropped from the
  search, which is therefore a **superset**; a branch with nothing expressible is "not searchable" and says so.
* Every returned log is normalised (now with `process.command_line` and `process.parent.name`) and must satisfy the behaviour's **full** condition
  locally (`ioa_matches`), the same check every upstream result already goes through, so a loose search can only cost time.
* Trend behaviours use their existing vendor query on `endpoint_activity` and the same local check.
* The sweep queue holds indicators and behaviours (`ioa:<id>`) of validated threats that have a case; behaviours join the same exact-progress
  window logic. Indicator batches run `sweep_parallel` (default 2) at a time. Hunts now also search LogRhythm for behaviours.
* A behaviour hit is filed in its threat's case. A lone behaviour stays MEDIUM (a lead for review, not a verdict).

**Not covered.** Built-in SIEM behaviours that belong to no threat (password spraying, privileged-group changes, WebLogic exploit paths) and Sigma
detection rules are not run upstream yet; they need a case policy of their own. Aggregate behaviours ("N failures from one IP") need thresholds over the returned logs.
