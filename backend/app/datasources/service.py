import hashlib
import hmac
import logging
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors import registry
from app.connectors.base import Connector
from app.core.config import Settings
from app.core.crypto import decrypt_json, encrypt_json
from app.datasources.models import DataSource
from app.datasources.schemas import DataSourceOut
from app.events import service as ingest_service
from app.events.search.base import SearchBackend

log = logging.getLogger("app.datasources")
KEY_PREFIX = "hk_"


def new_ingest_key() -> tuple[str, str]:
    raw = KEY_PREFIX + secrets.token_urlsafe(32)
    return raw, hash_key(raw)


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def key_matches(raw: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_key(raw), stored_hash)


def to_out(ds: DataSource, settings: Settings, ingest_key: str | None = None) -> DataSourceOut:
    secret_keys = sorted(decrypt_json(settings, ds.secrets_enc)) if ds.secrets_enc else []
    cls = registry._REGISTRY.get(ds.connector_type)  # noqa: SLF001
    return DataSourceOut(
        id=ds.id,
        name=ds.name,
        connector_type=ds.connector_type,
        config=ds.config,
        has_secrets=bool(secret_keys),
        secret_keys=secret_keys,
        enabled=ds.enabled,
        supports_collect=bool(cls and cls.supports_collect),
        health_status=ds.health_status,
        health_detail=ds.health_detail,
        health_checked_at=ds.health_checked_at,
        last_ingest_at=ds.last_ingest_at,
        events_total=ds.events_total,
        created_at=ds.created_at,
        ingest_key=ingest_key,
    )


def build_connector(ds: DataSource, settings: Settings) -> Connector:
    return registry.build(
        ds.connector_type, ds.config, {k: str(v) for k, v in decrypt_json(settings, ds.secrets_enc).items()}
    )


def encrypt_secrets(settings: Settings, data: dict[str, str]) -> bytes | None:
    return encrypt_json(settings, data) if data else None


async def ingest_batch(
    session: AsyncSession, backend: SearchBackend, settings: Settings, ds: DataSource, raw_events: list[dict[str, Any]]
) -> ingest_service.IngestResponse:
    req = ingest_service.IngestRequest(source_type=ds.connector_type, config=ds.config, events=raw_events)
    # IngestRequest builds its own connector from (type, config); pass secrets-free config only.
    response = await ingest_service.ingest(backend, ds.tenant_id, req)
    await session.execute(
        update(DataSource)
        .where(DataSource.id == ds.id)
        .values(
            last_ingest_at=datetime.now(UTC),
            events_total=DataSource.events_total + response.accepted,
            health_status="ok",
            health_detail=f"last batch: {response.accepted} accepted, {len(response.rejected)} rejected"[:300],
            health_checked_at=datetime.now(UTC),
        )
    )
    return response


async def collect_source(session: AsyncSession, backend: SearchBackend, settings: Settings, ds: DataSource) -> int:
    """Pull one batch from a pull-capable connector and ingest it. Failures only mark health; never raise."""
    try:
        connector = build_connector(ds, settings)
        since = datetime.fromisoformat(ds.cursor) if ds.cursor else None
        raws = [r async for r in connector.collect(since=since, limit=1000)]
        if not raws:
            await _mark(session, ds, "ok", "no new records")
            return 0
        events = [e for r in raws for e in _safe_normalize(connector, r)]
        from app.events.schema import Event

        staged = [Event.from_input(e, ds.tenant_id) for e in events]
        result = await backend.index_events(staged)
        newest = max((e.timestamp for e in events), default=None)
        await session.execute(
            update(DataSource)
            .where(DataSource.id == ds.id)
            .values(
                events_total=DataSource.events_total + result.accepted,
                last_ingest_at=datetime.now(UTC),
                cursor=newest.isoformat() if newest else ds.cursor,
                health_status="ok",
                health_detail=f"collected {result.accepted} new, {result.duplicates} duplicate"[:300],
                health_checked_at=datetime.now(UTC),
            )
        )
        return result.accepted
    except Exception as exc:
        log.warning("collection failed", extra={"data_source": str(ds.id), "error": type(exc).__name__})
        await _mark(session, ds, "down", f"{type(exc).__name__}: {str(exc)[:200]}")
        return 0


def _safe_normalize(connector: Connector, raw: dict[str, Any]) -> list[Any]:
    from app.connectors.base import NormalizationError

    try:
        return connector.normalize(raw)
    except NormalizationError:
        return []


async def _mark(session: AsyncSession, ds: DataSource, status: str, detail: str) -> None:
    await session.execute(
        update(DataSource)
        .where(DataSource.id == ds.id)
        .values(health_status=status, health_detail=detail, health_checked_at=datetime.now(UTC))
    )


async def find_by_key(session: AsyncSession, raw_key: str) -> DataSource | None:
    ds = (
        await session.execute(select(DataSource).where(DataSource.ingest_key_hash == hash_key(raw_key)))
    ).scalar_one_or_none()
    return ds if ds and ds.ingest_key_hash and key_matches(raw_key, ds.ingest_key_hash) else None


__all__ = ["uuid"]
