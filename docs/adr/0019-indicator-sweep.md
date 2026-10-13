# ADR 0019 — Sweep the SIEMs for indicators instead of copying their logs

**Status:** accepted. Builds on ADR 0013/0015/0018. Stages 1 and 2 (LogRhythm and Trend Vision One sweeps).

**Problem.** The LogRhythm connector pulled every log of one host (the DC) every 5 minutes, up to 20,000 per run, normalised and indexed all of it.
Almost none of it ever matched an indicator. Indicator searches (hunts, ADR 0018) already asked the SIEM for exactly the logs that contain an
indicator, but only when someone ran one, plus a 6-hourly re-hunt of watched threats.

**Decision.** A worker job (`sweep_iocs`, every 5 minutes) sweeps every LogRhythm source and every searchable Trend dataset
(`TREND_FIELDS`: endpoint, detections, identity) for the **validated indicators that already have a case**, over the time since the last
sweep, and imports only the logs that really contain one (the same whole-token attribution as a hunt). The platform stores evidence, not the stream.

* **Exact progress (`IocSweep`, one row per source).** `cursor` = everything before it was searched for every swept indicator. A window
  (`cursor - overlap` .. `min(cursor + max window, now - lag)`) is searched indicator-chunk by chunk (`queue`). On a SIEM error or when the
  tick budget runs out the queue keeps the rest and the cursor does **not** move: a slow or failing SIEM makes the sweep lag (shown in the status),
  it never skips data. An indicator that becomes sweepable while a window is in flight (`members`) is searched over that same window before it
  closes. A row lock (`lock_until`) keeps two workers off one source.
* **Hits** go to the indicator's case exactly like a watch-list re-hunt (evidence, activity note, severity, reopen), but a sweep does not set
  `last_hunted_at`: it covers SIEM logs only, so the 6-hourly full re-hunt (local index, behaviours) is unaffected. A sweep that finds only
  already-known events leaves no record.
* **Whole SIEM, not the DC.** The source's `hostname` restriction is not applied. Trend datasets are swept even when their collection is
  disabled for capacity.
* **Options (per source config).** `ioc_sweep` (default on), `sweep_lag_minutes`, `sweep_overlap_minutes`, `sweep_max_window_minutes`,
  `sweep_budget_s`. LogRhythm also gets `collect_vendor_message_ids`: keep only collected logs whose vendor message id (Windows event id) is
  listed, so the DC source can shrink to a small high-value stream (auth, Kerberos, privileged-group changes) that detections still need. It
  filters after the read, so it reduces what is stored, not what the SIEM is asked for.

**Limits.**
* Indicators are swept from the moment they have a case; before that their initial hunt (lookback days) covers them.
* The sweep is bounded by the SIEM, not by the platform: about a minute per 25 indicators over a long window, far less over 5 minutes. Over the
  budget it falls behind and says so; priority is by seen-in-telemetry then confidence, and every indicator is reached before the cursor moves.
* A Trend result cap on a very busy window is reported in the status, not hidden.
* Only indicator types the SIEM can filter on are swept (LogRhythm: ip, domain, url, hashes, email; Trend: per dataset). Other types
  (file names, registry keys, user agents, JA3) need the field-discovery step and are not swept yet.
* LogRhythm searches by log date; logs that arrive later than lag + overlap are missed by the sweep (the 6-hourly re-hunt still covers them).
