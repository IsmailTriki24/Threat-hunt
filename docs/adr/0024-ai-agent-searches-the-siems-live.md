# ADR 0024 — The AI hunting agent searches the SIEMs live

**Status:** accepted. Follows ADR 0023 (SIEM Search) and ADR 0019-0022 (collection switched off).

**Problem.** Every data tool of the agent read the platform's own stored copy of telemetry. Once the SIEMs stopped being copied into it, that copy
froze, so the agent could not see recent activity, and its `data_coverage` reported almost nothing stored, which made it conclude "nothing is
collected, nothing to hunt" without ever asking a SIEM.

**Decision.**
* **`siem_search`** (new tool): the live engine of the SIEM Search page (`events/siem_query.py`). Same query language, per-source translation, and local
  re-check of every record; each event says which source returned it. Slow (10-90 s), so it has **no per-run count limit by default** (`ai_siem_max_calls`, 0 = unlimited; an operator may set one; the run's step, time and token limits still bound it),
  has its own timeout (120 s), is **never retried** on a transient failure, and is served from the run cache when repeated. Honest statuses: a source
  that failed makes that part **UNANSWERED** (an error, not an empty result, unless other sources answered); conditions a source could not be asked are
  listed (`not_asked`); empty means only "no log matched in these sources and this window".
* **Evidence stays real.** Events the model is shown are stored (they are what it may cite) and entered in the run's ledger, so the evidence gate,
  conclusions, cases and reports work unchanged. Nothing else is stored.
* **`siem_findings`** (new tool): what the continuous sweep already found (built-in behaviour alerts and indicator matches), without querying a SIEM.
* **Coverage tells the truth.** `data_coverage` now lists the live sources and the event types each kind can hold, and the newest stored event. The agent
  merges those into its coverage (so playbook feasibility and "no process telemetry" gaps reflect the live sources) and `gate_reasons` no longer treats
  an empty stored copy as "nothing to hunt" while a live source exists. The state brief says the stored copy is frozen and not current.
* **Prompt.** The system prompt explains the two parts of the telemetry (live SIEMs vs frozen stored copy), what each SIEM holds, to start from
  `siem_findings`, to ask focused questions, and never to read an empty stored result as absence. `search_events` says it is the stored copy.
* The hunt report counts `siem_search` / `siem_findings` as telemetry and labels them.

**Limits.** The agent's SIEM view is as slow and as capped as the SIEM Search page (1,500 reads per search, 25 events shown per call, 14-day maximum
window). The stored-copy tools (`pivot_entity`, `events_around`, `process_lineage`) still operate on stored events only: to pivot on something found
live, search it again with `siem_search` (events it showed are stored and can be inspected with `get_event`).
