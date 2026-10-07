import ipaddress
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.assets.models import Asset
from app.core.errors import AppError
from app.events.search.base import SearchBackend
from app.investigations.iocs import is_internal_ip

# asset type -> event fields that identify it in telemetry (searched independently and merged: no OR in EventQuery)
EVENT_FIELDS: dict[str, list[str]] = {
    "host": ["host.hostname"],
    "server": ["host.hostname"],
    "user": ["user.name"],
    "ip": ["host.ip", "network.src_ip", "network.dst_ip", "auth.source_ip"],
    "domain": ["network.dst_domain", "dns.question"],
    "application": ["process.name"],
    "cloud": ["host.id"],
}


def normalize_key(type_: str, key: str) -> str:
    k = key.strip().lower()
    if not k:
        raise AppError("Asset key must not be empty")
    if type_ == "ip":
        try:
            return str(ipaddress.ip_address(k))
        except ValueError:
            raise AppError("Invalid IP address") from None
    if type_ == "user" and "\\" in k:
        k = k.rsplit("\\", 1)[-1]  # DOMAIN\user -> user (telemetry stores domain separately)
    return k


async def upsert_seen(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    type_: str,
    key: str,
    display: str | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    event_count: int = 0,
) -> Asset:
    """Create the asset if unknown; widen its seen-window if known. Never downgrades analyst-set fields."""
    key = normalize_key(type_, key)
    stmt = (
        insert(Asset)
        .values(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            type=type_,
            key=key,
            display_name=display or key,
            tags=[],
            attributes={},
            event_count=event_count,
            first_seen=first_seen,
            last_seen=last_seen,
        )
        .on_conflict_do_nothing(constraint="uq_asset_identity")
    )
    await session.execute(stmt)
    asset = (
        await session.execute(select(Asset).where(Asset.tenant_id == tenant_id, Asset.type == type_, Asset.key == key))
    ).scalar_one()
    # `server` is an analyst refinement of `host`; keep hosts addressable under either identity.
    if first_seen and (asset.first_seen is None or first_seen < asset.first_seen):
        asset.first_seen = first_seen
    if last_seen and (asset.last_seen is None or last_seen > asset.last_seen):
        asset.last_seen = last_seen
    if event_count:
        asset.event_count = max(asset.event_count, event_count)
    return asset


async def assets_from_events(session: AsyncSession, tenant_id: uuid.UUID, docs: list[dict[str, Any]]) -> list[Asset]:
    found: dict[tuple[str, str], tuple[datetime, datetime]] = {}
    for d in docs:
        ts = datetime.fromisoformat(d["timestamp"].replace("Z", "+00:00"))
        candidates: list[tuple[str, str | None]] = [
            ("host", (d.get("host") or {}).get("hostname")),
            ("user", (d.get("user") or {}).get("name")),
        ]
        for ip in (d.get("host") or {}).get("ip", []) or []:
            if is_internal_ip(ip):
                candidates.append(("ip", ip))
        for type_, key in candidates:
            if key:
                lo, hi = found.get((type_, key.lower()), (ts, ts))
                found[(type_, key.lower())] = (min(lo, ts), max(hi, ts))
    assets = []
    for (type_, key), (lo, hi) in found.items():
        # an analyst may have promoted the host to a server; reuse whichever identity exists
        existing = None
        if type_ == "host":
            existing = (
                await session.execute(
                    select(Asset).where(Asset.tenant_id == tenant_id, Asset.type == "server", Asset.key == key)
                )
            ).scalar_one_or_none()
        assets.append(existing or await upsert_seen(session, tenant_id, type_, key, first_seen=lo, last_seen=hi))
    return assets


async def discover(session: AsyncSession, backend: SearchBackend, tenant_id: uuid.UUID, days: int) -> tuple[int, int]:
    end = datetime.now(UTC)
    start = end - timedelta(days=days)
    created = updated = 0
    for field, type_ in (("host.hostname", "host"), ("user.name", "user"), ("host.ip", "ip")):
        for d in await backend.distinct_values(tenant_id, field, start.isoformat(), end.isoformat(), size=1000):
            if type_ == "ip" and not is_internal_ip(d.key):
                continue
            key = normalize_key(type_, d.key)
            lookup_types = ["host", "server"] if type_ == "host" else [type_]
            existing = (
                (
                    await session.execute(
                        select(Asset).where(
                            Asset.tenant_id == tenant_id, Asset.type.in_(lookup_types), Asset.key == key
                        )
                    )
                )
                .scalars()
                .first()
            )
            first = datetime.fromisoformat(d.first_seen.replace("Z", "+00:00")) if d.first_seen else None
            last = datetime.fromisoformat(d.last_seen.replace("Z", "+00:00")) if d.last_seen else None
            if existing is None:
                await upsert_seen(session, tenant_id, type_, key, first_seen=first, last_seen=last, event_count=d.count)
                created += 1
            else:
                await upsert_seen(
                    session, tenant_id, existing.type, key, first_seen=first, last_seen=last, event_count=d.count
                )
                updated += 1
    return created, updated
