# ruff: noqa: E501
import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import asyncpg
import httpx
import pytest
import pytest_asyncio

ROOT = Path(__file__).resolve().parents[2]


def _dotenv() -> dict[str, str]:
    path = ROOT / ".env"
    out: dict[str, str] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                out[k.strip()] = v.strip().strip('"')
    return out


_env = {**_dotenv(), **os.environ}
_pg = f"{_env.get('POSTGRES_USER', 'hunt')}:{_env.get('POSTGRES_PASSWORD', 'hunt')}"
TEST_DB = _env.get("TEST_DB_NAME", "hunt_test")  # override to run several suites concurrently
ADMIN_DSN = f"postgresql://{_pg}@{_env.get('PG_HOST', 'localhost')}:{_env.get('POSTGRES_PORT', '5432')}/postgres"
os.environ.update(
    APP_ENV="test",
    DATABASE_URL=f"postgresql+asyncpg://{_pg}@{_env.get('PG_HOST', 'localhost')}:{_env.get('POSTGRES_PORT', '5432')}/{TEST_DB}",
    REDIS_URL=f"redis://:{_env.get('REDIS_PASSWORD', '')}@localhost:{_env.get('REDIS_PORT', '6379')}/{_env.get('TEST_REDIS_DB', '15')}",
    OPENSEARCH_URL=f"http://localhost:{_env.get('OPENSEARCH_PORT', '9200')}",
    INDEX_PREFIX=_env.get("TEST_INDEX_PREFIX", "test-"),
    JWT_SECRET="test-secret-test-secret-test-secret-0123456789",
    LOG_LEVEL="WARNING",
    SEED_DEMO_DATA="false",
)
os.environ.pop("METRICS_TOKEN", None)

from app.auth.rbac import Role  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.core.security import create_access_token, hash_password  # noqa: E402
from app.events.schema import EventIn  # noqa: E402
from app.main import create_app  # noqa: E402
from app.tenants.models import Tenant  # noqa: E402
from app.users.models import Membership, User  # noqa: E402

PASSWORD = "Correct-Horse-Battery-9"


@pytest.fixture(scope="session", autouse=True)
def _database() -> None:
    import asyncio

    async def recreate() -> None:
        conn = await asyncpg.connect(ADMIN_DSN)
        await conn.execute(f"DROP DATABASE IF EXISTS {TEST_DB} WITH (FORCE)")
        await conn.execute(f"CREATE DATABASE {TEST_DB}")
        await conn.close()

    asyncio.run(recreate())
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=ROOT / "backend", check=True)  # noqa: S603


@pytest_asyncio.fixture(scope="session")
async def app() -> AsyncIterator[Any]:
    application = create_app()
    async with application.router.lifespan_context(application):
        await application.state.search.ensure_schema()
        yield application
        await application.state.opensearch.indices.delete(index=f"{get_settings().index_prefix}*")
        await application.state.opensearch.indices.delete_index_template(name=f"{get_settings().index_prefix}telemetry")


@pytest_asyncio.fixture
async def client(app: Any) -> AsyncIterator[httpx.AsyncClient]:
    await app.state.redis.flushdb()  # fresh rate-limit counters per test
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def db(app: Any) -> AsyncIterator[Any]:
    async with app.state.sessionmaker() as session:
        yield session


class Factory:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def tenant(self, name: str | None = None) -> Tenant:
        slug = f"t-{uuid.uuid4().hex[:10]}"
        async with self.app.state.sessionmaker() as s:
            t = Tenant(slug=slug, name=name or slug)
            s.add(t)
            await s.commit()
            return t

    async def user(self, tenant: Tenant | None, role: Role | None, *, super_admin: bool = False) -> User:
        async with self.app.state.sessionmaker() as s:
            u = User(
                email=f"u-{uuid.uuid4().hex[:10]}@test.example",
                password_hash=hash_password(PASSWORD),
                is_super_admin=super_admin,
            )
            s.add(u)
            await s.flush()
            if tenant and role:
                s.add(Membership(user_id=u.id, tenant_id=tenant.id, role=role.value))
            await s.commit()
            return u

    def headers(self, user: User, tenant: Tenant | None) -> dict[str, str]:
        token, _ = create_access_token(get_settings(), user_id=user.id, tenant_id=tenant.id if tenant else None)
        return {"authorization": f"Bearer {token}"}

    async def login_as(self, tenant: Tenant, role: Role) -> tuple[User, dict[str, str]]:
        u = await self.user(tenant, role)
        return u, self.headers(u, tenant)

    async def index(self, tenant: Tenant, events: list[EventIn]) -> None:
        from app.events.schema import Event

        backend = self.app.state.search
        result = await backend.index_events([Event.from_input(e, tenant.id) for e in events])
        assert not result.failed, result.failed
        await self.app.state.opensearch.indices.refresh(index=backend.pattern, ignore_unavailable=True)


@pytest.fixture
def make(app: Any) -> Factory:
    return Factory(app)
