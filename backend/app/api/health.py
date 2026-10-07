import asyncio
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from app.core.config import get_settings
from app.core.errors import NotFound

router = APIRouter(tags=["ops"])

WORKER_HEARTBEAT_KEY = "worker:heartbeat"


@router.get("/health")
async def health() -> dict[str, str]:
    """Liveness: the process is up and serving."""
    return {"status": "ok"}


async def _check(coro: Any) -> dict[str, Any]:
    try:
        return await asyncio.wait_for(coro, timeout=3)
    except Exception:
        return {"status": "down"}


@router.get("/ready")
async def ready(request: Request) -> JSONResponse:
    """Readiness: dependencies required to serve traffic. Worker is reported but non-blocking."""
    state = request.app.state

    async def db() -> dict[str, Any]:
        async with state.sessionmaker() as s:
            await s.execute(text("select 1"))
        return {"status": "ok"}

    async def redis() -> dict[str, Any]:
        await state.redis.ping()
        return {"status": "ok"}

    async def worker() -> dict[str, Any]:
        beat = await state.redis.get(WORKER_HEARTBEAT_KEY)
        return {"status": "ok" if beat else "down"}

    postgres, redis_, search, worker_ = await asyncio.gather(
        _check(db()), _check(redis()), _check(state.search.health()), _check(worker())
    )
    components = {"postgres": postgres, "redis": redis_, "opensearch": search, "worker": worker_}
    critical_ok = all(components[c]["status"] != "down" for c in ("postgres", "redis", "opensearch"))
    body = {"status": "ready" if critical_ok else "not_ready", "components": components}
    return JSONResponse(body, status_code=200 if critical_ok else 503)


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> Response:
    settings = get_settings()
    token = settings.metrics_token
    if token:
        if request.headers.get("authorization") != f"Bearer {token}":
            raise NotFound("Not found")
    elif settings.app_env == "production":
        raise NotFound("Not found")  # disabled unless explicitly protected with METRICS_TOKEN
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
