# ADR 0011 — AI hunting

**Status:** accepted (Milestone 6)

**Optional and isolated.** `AI_PROVIDER=none` (default) disables it; no other feature depends on it. Provider credentials come only
from the environment (never the DB, never the browser). `LLMProvider` is a small protocol (`complete(system, messages, tools)`); the
Anthropic adapter is the first implementation and speaks the Messages API over httpx. Failures surface as a safe
`ProviderUnavailable` message (no keys, no upstream bodies).

**The model can only call tools.** `search_events`, `aggregate_events`, `get_event`, `lookup_ioc` (cached tenant intel only — no
outbound calls) and `mitre_technique`, all read-only. Each takes pydantic-typed input, runs as the *invoking user's* `Principal`
(tenant scope and RBAC unchanged; the model is only offered tools its user may use), and has bounded output. Model-written
queries pass through the same `EventQuery`/DSL validation as human ones. Step, tool-call and wall-clock budgets apply; the final
turn offers only `submit_conclusion`.

**Untrusted data.** Tool results are wrapped in an `untrusted_data` envelope and the system prompt forbids following instructions
found in event content. Defence does not rest on the prompt: the worst a manipulated model can do is issue more read-only,
permission-checked searches.

**Conclusions are verified, not believed.** A per-run ledger records every event the model was actually shown. The validator
discards cited ids not in the ledger, drops unknown ATT&CK ids, marks findings without verified evidence `supported=false`
(they cannot be saved), and lowers confidence to LOW when nothing is supported. Saving to a hunt re-reads evidence from telemetry
(tenant-scoped), titles findings `[AI]` and records provenance. The UI always shows the model's claimed vs. validated confidence.

**Auditability.** Each run persists its goal, tool trace, tokens and validated conclusion (`ai_runs`); runs are private to their
author (tenant admins can see all). Every run, translation and save is also audit-logged.

**NL → query.** Output is parsed and validated; invalid output is fed back once, then refused.

**Not in scope:** autonomous actions (no write tools), streaming/background runs (runs are synchronous with a timeout and a
per-user rate limit), multi-provider routing, per-tenant provider credentials.
