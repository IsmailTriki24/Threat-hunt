# ADR 0014 — Threat bulletins (IOC + IOA + TTP under a named threat)

**Status:** accepted. Extends ADR 0013.

**Why.** Analysts do not triage thousands of loose indicators; they decide about *threats*. The unit of work is now a **bulletin**: a named
threat (malware family, actor, campaign or report) with its indicators of compromise (IOCs), indicators of attack (IOAs, behaviours) and
ATT&CK techniques (TTPs). One decision — validate the bulletin — hunts all of it.

**Grouping (`threats.py`).** Each feed says which threat an indicator belongs to (ThreatFox/Feodo: family; OTX: adversary else pulse name; MISP:
event title; URLhaus: first non-generic tag). Names are normalised and resolved through ATT&CK software/group aliases (QBot = QakBot), so
one threat is one row. Generic tags ('github', 'elf', 'zip'), addresses and the platform's own feed markers are never names; an indicator
with no name falls into "Unattributed <role> (<source>)" so nothing is hidden. A full regroup re-derives every name and removes bulletins left empty.

**TTPs.** In order of trust: MITRE-documented usage (the full ATT&CK dataset incl. software and groups is loaded with `mitre-load`), techniques the
feed declared, techniques implied by the indicator's role. Unknown techniques are never invented.

**IOAs.** Behaviours as `Condition` trees (the detection engine's representation), validated against the field registry at import, with an
optional equivalent Trend Vision One query: a built-in catalogue linked by technique, plus the tenant's own ACTIVE/TESTING detection rules, plus
analyst-authored ones. Every upstream result is re-verified against the same Condition. Two traps found on live data are encoded in the code and
tests: on analysed text fields an any-of list means *equals* (so command lines use per-token `contains`), and Vision One reports process names as
full paths (so queries use the suffix form and the normalizer stores the file name, with the path in `executable`).

**Hunt.** Validating a bulletin creates one hunt over its indicators (prioritised, up to 500 now; the rest follow in scheduled batches,
never-hunted first), its behaviours (ingested telemetry + Trend upstream) and its techniques (events a security product already tagged with them).
IOC matches are strong evidence; a behaviour or technique alone is a lead that raises a case for review and never closes it; a behaviour on the
same host as an indicator raises severity one level. Severity of a *bulletin* follows evidence (CRITICAL only for ransomware or when already
visible in the tenant's telemetry), not the feed's confidence. Re-validating a hunted bulletin appends to the same case and rescans the full lookback.

**Lessons recorded.** Oversized attacker-controlled values (a 30 KB base64 command line) are truncated and labelled, never allowed to drop the event.
Catalogue behaviours refresh into existing threats, so a corrected detector reaches bulletins that already exist; manual ones are never touched.
