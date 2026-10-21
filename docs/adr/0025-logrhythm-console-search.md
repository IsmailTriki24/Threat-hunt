# ADR 0025 — LogRhythm is searched through the Web Console, not the Search API

**Status:** accepted. Replaces the *transport* of ADR 0012/0015/0018/0020/0021/0023; the filters, planning and local verification they describe are unchanged.

**Problem.** The `:8501` Search API returns normalized metadata only. The raw log text (`logMessage`) never comes back, an analyst could not see
what a log said, and the API has no query language beyond numeric filter codes. The Web Console, which analysts already use, returns the raw text
next to the metadata and answers Lucene.

**Decision.** Every LogRhythm search of the platform (the SIEM search page, hunts, sweeps, behaviours, the AI agent) goes through the console's own
socket.io service (`app/connectors/logrhythm_console.py`). `LogRhythmConnector._search_window` is the single seam: it takes the same query filters
as before and returns the same raw log dicts, so planning, attribution, cap-splitting and normalization did not change. The Search API is no longer
called; nothing falls back to it.

**Protocol** (verified on a production LogRhythm 7.x, 2026-10-21; it is the console's internal protocol, not a documented API):
* Login: `GET /api/webconsole/config.js` issues `_csrf` + `XSRF-TOKEN`; `POST /api/webconsole/login` `{username,password,_csrf}` + header
  `XSRF-TOKEN` answers 200 + `connect.sid`.
* Socket: `wss://host:8443/api/webconsole/socket.io/` (Engine.IO v4, written on `websockets`; no new dependency). A search is a task:
  `TaskService/CreateSearchRequest` -> poll `GetTaskRequest` (`shortResults`, `numResults`) -> `LogsService/LogsRequest` pages of 200 ->
  `RemoveTasksRequest`. The search configuration is the Search tool's own (`searchType 1`, `queryRawLog true`).
* The server-side filter is only honoured when the top filter group carries `filterType: 1000`; `searchMode 3` keeps the NEWEST results of a capped
  search (without it a task stops at 10,000).

**Behaviour.**
* An interactive search stops as soon as enough results exist (`max_logs`, newest first) instead of waiting for the 30,000-log cap; a sweep waits for
  the whole task and a window that hits the cap is split in half, as before. Measured: 5-12 s for a scoped search, ~27 s to collect 30,000 logs,
  ~70 s more to page them all (200 per page), so full reads belong in narrow windows.
* A bare word is now ONE search on the raw log text (the console returns it, and every result is still re-checked locally); it used to be nine.
* One logged-in session and one socket per console account and event loop, shared by all searches; at most `console_parallel` (default 2, max 5)
  searches at a time, because the console serves a handful of simultaneous searches. A connection that dies is reopened once.
* Every task is removed when its search ends, so nothing accumulates in the account's task list.

**Security.**
* Credentials are the data source secrets `username` and `password` (encrypted at rest, write-only). Use a DEDICATED read-only account without
  multi-factor authentication; never a person's account.
* The outbound SSRF policy covers the login AND the socket: the host is resolved once, validated, and the connection is pinned to that address with
  the certificate name from `console_tls_server_name`. The console serves a different certificate than `:8501`, so it has its own pin
  (`console_ca_pem`, falling back to `ca_pem`). Port 8443 must be in `OUTBOUND_ALLOWED_PORTS`.
* A refused login is not retried for five minutes, so a wrong password cannot lock the account. No error, log line or `repr` carries a credential.

**Config** (all on the existing `logrhythm` data source): `console_url`, `console_verify_tls`, `console_ca_pem`, `console_tls_server_name`,
`console_parallel`, `console_poll_s`, `console_task_timeout_s`; `base_url` (the old gateway) is now optional.

**Not covered / follow-ups.** The alarm feed and the entity / log-source-type pickers still need the Alarm and Admin APIs (`base_url` + `token`); without
them the search page says so and carries on. The console also offers Lucene, top-N and trend aggregations and distinct-value lookups
(`TypeaheadService`), which this ADR does not use yet. The protocol can change with a LogRhythm upgrade: the client is isolated in one module and
fails with a clean `ConsoleError`.

**Tests.** `tests/test_logrhythm_console.py` drives the real client over a fake socket (login, framing, ping, paging, early stop, reconnect, lockout
protection, SSRF) and over a real TLS websocket server (certificate pinning, hostname check). The other suites use `tests/fake_console.py`, which
answers a console search with the same SIEM handlers they always used.
