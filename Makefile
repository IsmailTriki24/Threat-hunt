.PHONY: env up down infra init backend-dev backend-test backend-check frontend-check check

env:            ## create .env with random secrets
	./scripts/init-env.sh
up:             ## whole stack
	docker compose up -d --build
down:
	docker compose down
infra:          ## only datastores (for local backend/frontend dev)
	docker compose up -d postgres redis opensearch minio
init:           ## migrate + provision OpenSearch + seed (uses backend/.venv and ../.env)
	cd backend && set -a && . ../.env && set +a && \
	DATABASE_URL=postgresql+asyncpg://$$POSTGRES_USER:$$POSTGRES_PASSWORD@localhost:$$POSTGRES_PORT/$$POSTGRES_DB \
	REDIS_URL=redis://:$$REDIS_PASSWORD@localhost:$$REDIS_PORT/0 OPENSEARCH_URL=http://localhost:$$OPENSEARCH_PORT \
	.venv/bin/python -m app.cli init
backend-test:
	cd backend && .venv/bin/pytest -q
backend-check:
	cd backend && .venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/mypy app && \
	.venv/bin/bandit -q -r app -c pyproject.toml && .venv/bin/pip-audit && .venv/bin/pytest -q
frontend-check:
	cd frontend && npm run lint && npm run typecheck && npm test && npm run build
check: backend-check frontend-check
