# ADR 0006 — Connector interface

**Status:** accepted

`Connector` (ABC) declares `connector_type`, a typed `config_model`, `test_connection()`, `collect()` (pull),
`normalize()` (pure, sync, `raw → list[EventIn]`) and `health()`. Differences from the brief's sketch:
`normalize` is synchronous because it is pure CPU; push-only sources set `supports_collect = False`.
The core only talks to `connectors.registry`; adding a source is one module + one `register()` call.

Milestone 1 ships `canonical`, `generic_json` (declarative field map; unknown target fields are rejected) and
`sysmon` (EventID 1/3/11/22). Wazuh, Zeek, Suricata, Windows Event Log, REST and OpenSearch-pull connectors
and the persisted `DataSource` entity (with credentials in a secret store) come with Milestone 3.
Connector configs never contain executable content; field maps are data, not code.
