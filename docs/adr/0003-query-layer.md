# ADR 0003 — Engine-neutral query model, no raw DSL

**Status:** accepted

## Decision
Clients express searches as `EventQuery` (free text, typed filters, time range, sort, pagination, aggregations).
Fields come from a **field registry** (`events/fields.py`) that also generates the OpenSearch mapping
(`dynamic: strict`). Operators are allow-listed per field kind, values are coerced and validated, sort and
aggregation fields must be flagged sortable/aggregatable, sizes and result windows are capped. Free text uses
`simple_query_string` (no field selectors, regex, fuzzy or wildcard-on-field syntax) with an upper-case
`AND`/`OR`/`NOT` translation for analyst ergonomics. Raw OpenSearch DSL is never accepted.

## Consequences
* Injection resistance is structural: a field/operator that isn't in the registry cannot be expressed.
* Another engine implements `SearchBackend` and compiles the same `EventQuery`.
* Power users cannot write arbitrary DSL. Later milestones add a validated hunt query language that compiles
  to `EventQuery`, and the AI layer must target the same model (so generated queries are validated by the
  same code path as human ones).
