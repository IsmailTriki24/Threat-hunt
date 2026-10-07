import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from opensearchpy import AsyncOpenSearch
from redis.asyncio import Redis

from app.api.health import router as health_router
from app.api.router import api_router
from app.core.config import Settings, get_settings
from app.core.db import create_engine, create_sessionmaker
from app.core.errors import install_error_handlers
from app.core.logging import configure_logging
from app.core.middleware import BodyLimitMiddleware, install_http_middleware
from app.events.search.opensearch import OpenSearchBackend

log = logging.getLogger("app")


def make_opensearch(settings: Settings) -> AsyncOpenSearch:
    auth = (settings.opensearch_username, settings.opensearch_password) if settings.opensearch_username else None
    return AsyncOpenSearch(
        hosts=[settings.opensearch_url],
        http_auth=auth,
        verify_certs=settings.opensearch_verify_certs,
        timeout=20,
        max_retries=2,
        retry_on_timeout=True,
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    engine = create_engine(settings)
    app.state.engine = engine
    app.state.sessionmaker = create_sessionmaker(engine)
    app.state.redis = Redis.from_url(settings.redis_url, decode_responses=True)
    os_client = make_opensearch(settings)
    app.state.opensearch = os_client
    app.state.search = OpenSearchBackend(os_client, settings)
    log.info("application started", extra={"env": settings.app_env})
    try:
        yield
    finally:
        await app.state.redis.aclose()
        await os_client.close()
        await engine.dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    prod = settings.app_env == "production"
    app = FastAPI(
        title="Threat Hunting Platform API",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None if prod else "/docs",
        redoc_url=None,
        openapi_url=None if prod else "/openapi.json",
    )
    install_error_handlers(app)
    install_http_middleware(app)
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)
    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
        )
    app.include_router(health_router)
    app.include_router(api_router)
    return app


app = create_app()
