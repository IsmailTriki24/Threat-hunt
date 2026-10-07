# Contributing

* Conventional commits: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`, `security:`.
* A change is done when it has tests (incl. authorisation + tenant-isolation tests for new endpoints), passes
  `make check`, and updates docs/ADRs when it changes architecture or security behaviour.
* New tenant-owned table ⇒ `tenant_id` column + handlers filtered by `principal.tid` + an isolation test.
* New endpoint ⇒ `Depends(require(Permission.…))`, an audit record for sensitive reads/writes, request models with `extra="forbid"`.
* New data source ⇒ a `Connector` + registry entry + normalisation tests (including malformed input).
* Never accept raw query DSL, tenant ids, or executable content from clients.

## Dev loop
```
make infra            # postgres, redis, opensearch, minio
make backend-test     # pytest (needs infra)
make check            # lint + typecheck + security + tests (backend and frontend)
```
