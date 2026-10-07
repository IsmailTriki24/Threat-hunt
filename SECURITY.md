# Security

## Reporting
Report vulnerabilities privately to the maintainers; do not open public issues for undisclosed flaws.

## Security model (implemented)
| Area | Control |
|---|---|
| Tenant isolation | derived server-side from DB-validated membership; mandatory tenant filter in the search layer; 404 for foreign objects; dedicated test suite (`tests/test_tenant_isolation.py`) |
| Authn | Argon2id; uniform login errors; per-IP and per-email rate limits; 15-min access JWT (alg pinned, aud/iss required); rotating single-use refresh tokens with reuse detection; HttpOnly+SameSite=Strict cookie + CSRF header |
| Authz | server-side `require(Permission)` on every route; roles re-read from DB each request; denied attempts audited |
| Query injection | no raw DSL; field/operator/sort/agg allow-lists from the field registry; typed value coercion; free text via `simple_query_string` with a restricted flag set; `dynamic: strict` mapping |
| SQL injection | SQLAlchemy parameterised queries only |
| Input limits | body-size cap (incl. chunked), batch caps, field length caps, `raw` ≤ 64 KiB, window/size caps |
| XSS | JSON-only API with `CSP: default-src 'none'`; frontend renders values as text only (no `dangerouslySetInnerHTML`) |
| Outbound HTTP | `core/ssrf.py`: public-address-only, IP pinning, re-validated redirects, port allow-list, size cap |
| Secrets at rest | data-source secrets Fernet-encrypted; ingest keys stored as SHA-256 only |
| Exports | capped, rate-limited, audited; CSV formula-injection neutralised |
| Errors | generic 500s with request id; validation errors strip echoed input |
| Audit | append-only table (trigger-enforced); logins, denials, user/tenant changes, searches, views, ingests |
| Secrets | from environment only; startup fails when `JWT_SECRET` is missing/short, or a `dev-only-*` placeholder is used outside `development` |
| Config hardening | OpenAPI/docs disabled in production; `/metrics` disabled in production unless `METRICS_TOKEN` is set |
| Deps | `pip-audit`, `bandit`, `ruff` (flake8-bandit rules), `mypy --strict` |

## Known gaps / production checklist
* OpenSearch runs **without** its security plugin in `docker-compose.yml` (loopback-only). Production: enable TLS + authn,
  per-service roles, ideally document-level security keyed on `tenant_id` as defence in depth.
* Terminate TLS in front of the stack and set `APP_ENV=production` (enables `Secure` cookies and the checks above).
* The rate limiter trusts the socket peer address; behind a proxy configure trusted proxy headers (`--forwarded-allow-ips`).
* No MFA/SSO, password reset or account lockout (only rate limiting) yet. Connector auth uses per-source ingest keys (rotatable).
* HS256 signing key is shared by anything that verifies tokens; move to asymmetric keys when more services verify.
* Creating a user with an e-mail that exists in another tenant returns 409 (limited enumeration by tenant admins).
* Outbound fetches (pull connectors today, enrichment adapters in M4) must go through `core/ssrf.py`. Network-level egress policy
  (firewall / proxy allow-list) is still recommended as a second layer.
* Any future tool execution (response actions, AI tools) must go through an explicit, audited boundary; nothing in this
  codebase executes commands derived from events, IOCs, queries or model output.
