import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import ssrf
from app.core.config import Settings
from app.core.crypto import decrypt_json
from app.core.errors import AppError
from app.events.search.base import SearchBackend
from app.events.search.query import Aggregation, EventQuery, Filter, TimeRange
from app.intel import stix as stix_lib
from app.intel import types
from app.intel.models import IntelEntity, IntelObservation, IntelProvider, IntelRelation
from app.intel.providers import PROVIDERS
from app.intel.providers.base import Context, Provider, ProviderResult
from app.intel.schemas import Coverage
from app.intel.scoring import Signal, score

log = logging.getLogger("app.intel")
TTL_OK = timedelta(hours=6)
TTL_ERROR = timedelta(minutes=5)
PROVIDER_TIMEOUT_S = 12.0
CONCURRENCY = 6


@dataclass
class ProviderState:
    provider: Provider
    enabled: bool
    config: dict[str, Any]
    secrets: dict[str, str]
    row: IntelProvider | None

    def context(self, entity: IntelEntity) -> Context:
        return Context(self.config, self.secrets, entity.watch_verdict, entity.watch_confidence)

    @property
    def configured(self) -> bool:
        return self.provider.offline or self.provider.configured(Context(self.config, self.secrets))


async def provider_states(session: AsyncSession, settings: Settings, tenant_id: uuid.UUID) -> dict[str, ProviderState]:
    rows = {
        r.provider: r
        for r in (await session.execute(select(IntelProvider).where(IntelProvider.tenant_id == tenant_id))).scalars()
    }
    states: dict[str, ProviderState] = {}
    for key, p in PROVIDERS.items():
        row = rows.get(key)
        secrets = (
            {k: str(v) for k, v in decrypt_json(settings, row.secrets_enc).items()} if row and row.secrets_enc else {}
        )
        enabled = row.enabled if row else p.offline
        states[key] = ProviderState(p, enabled, dict(row.config) if row else {}, secrets, row)
    return states


# ---- entities ------------------------------------------------------------------------------------------
async def upsert_entity(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    type_: str,
    value: str,
    *,
    source: str,
    user_id: uuid.UUID | None = None,
) -> IntelEntity:
    norm = types.normalize(type_, value)
    if norm is None:
        raise AppError(f"Invalid {type_} value")
    await session.execute(
        insert(IntelEntity)
        .values(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            type=type_,
            value=norm,
            source=source,
            created_by=user_id,
            tags=[],
            score_breakdown=[],
            notes="",
        )
        .on_conflict_do_nothing(constraint="uq_intel_entity")
    )
    return (
        await session.execute(
            select(IntelEntity).where(
                IntelEntity.tenant_id == tenant_id, IntelEntity.type == type_, IntelEntity.value == norm
            )
        )
    ).scalar_one()


async def rescore(session: AsyncSession, entity: IntelEntity) -> None:
    obs = (
        (await session.execute(select(IntelObservation).where(IntelObservation.entity_id == entity.id))).scalars().all()
    )
    signals = [Signal(o.provider, o.verdict, o.confidence, o.summary) for o in obs if o.status == "ok"]
    if entity.watch_verdict and not any(s.provider == "watchlist" for s in signals):
        signals.append(Signal("watchlist", entity.watch_verdict, entity.watch_confidence or 70, "Tenant watch-list"))
    entity.score, entity.verdict, entity.score_breakdown = score(signals)


# ---- provider execution --------------------------------------------------------------------------------
async def _run(state: ProviderState, entity: IntelEntity, sem: asyncio.Semaphore) -> ProviderResult:
    async with sem:
        try:
            return await asyncio.wait_for(
                state.provider.lookup(state.context(entity), entity.type, entity.value), PROVIDER_TIMEOUT_S
            )
        except ssrf.SsrfError as exc:
            return ProviderResult("error", summary=f"blocked by outbound policy: {exc}"[:300])
        except TimeoutError:
            return ProviderResult("error", summary="provider timed out")
        except httpx.HTTPError as exc:
            return ProviderResult("error", summary=f"network error ({type(exc).__name__})")
        except ValueError as exc:
            return ProviderResult("error", summary=str(exc)[:200] or "invalid provider response")
        except Exception:
            log.exception("provider crashed", extra={"provider": state.provider.key})
            return ProviderResult("error", summary="internal provider error")


@dataclass
class Plan:
    entity: IntelEntity
    cached: set[str] = field(default_factory=set)
    skipped: list[dict[str, str]] = field(default_factory=list)
    tasks: dict[str, ProviderState] = field(default_factory=dict)


async def _plan(
    session: AsyncSession, entity: IntelEntity, states: dict[str, ProviderState], refresh: bool, only: list[str] | None
) -> Plan:
    plan = Plan(entity)
    existing = {
        o.provider: o
        for o in (
            await session.execute(select(IntelObservation).where(IntelObservation.entity_id == entity.id))
        ).scalars()
    }
    now = datetime.now(UTC)
    for key, st in states.items():
        if only is not None and key not in only:
            continue
        if entity.type not in st.provider.supported_types:
            continue
        if not st.enabled:
            plan.skipped.append({"provider": key, "reason": "disabled"})
        elif not st.configured:
            plan.skipped.append({"provider": key, "reason": "not configured"})
        else:
            obs = existing.get(key)
            ttl = TTL_OK if obs and obs.status in ("ok", "not_found") else TTL_ERROR
            if not st.provider.offline and not refresh and obs and now - obs.fetched_at < ttl:
                plan.cached.add(key)
            else:
                plan.tasks[key] = st
    return plan


async def enrich_many(
    session: AsyncSession,
    settings: Settings,
    tenant_id: uuid.UUID,
    entities: list[IntelEntity],
    *,
    refresh: bool = False,
    only: list[str] | None = None,
) -> dict[uuid.UUID, Coverage]:
    """Network phase runs concurrently (bounded); database writes are applied afterwards, sequentially."""
    states = await provider_states(session, settings, tenant_id)
    plans = [await _plan(session, e, states, refresh, only) for e in entities if e.type in types.INDICATOR_TYPES]
    sem = asyncio.Semaphore(CONCURRENCY)
    jobs = [(p, key, asyncio.create_task(_run(st, p.entity, sem))) for p in plans for key, st in p.tasks.items()]
    results = {(p.entity.id, key): await task for p, key, task in jobs}
    out: dict[uuid.UUID, Coverage] = {}
    for p in plans:
        answered = failed = not_found = 0
        for key in p.tasks:
            res = results[(p.entity.id, key)]
            await _store(session, tenant_id, p.entity, key, res)
            answered += res.status == "ok"
            failed += res.status == "error"
            not_found += res.status == "not_found"
        p.entity.last_enriched_at = datetime.now(UTC)
        await session.flush()
        await rescore(session, p.entity)
        out[p.entity.id] = Coverage(
            answered=answered + len(p.cached), failed=failed, not_found=not_found, skipped=p.skipped
        )
    return out


async def _store(
    session: AsyncSession, tenant_id: uuid.UUID, entity: IntelEntity, key: str, res: ProviderResult
) -> None:
    values = dict(
        tenant_id=tenant_id,
        entity_id=entity.id,
        provider=key,
        status=res.status,
        verdict=res.verdict,
        confidence=res.confidence,
        summary=res.summary[:500],
        data=res.data,
        fetched_at=datetime.now(UTC),
    )
    stmt = insert(IntelObservation).values(id=uuid.uuid4(), **values)
    await session.execute(stmt.on_conflict_do_update(constraint="uq_intel_observation", set_=values))
    for hint in res.relations:
        named = types.normalize(hint.type, hint.value)
        if named is None:
            continue
        other = await upsert_entity(session, tenant_id, hint.type, named, source="lookup")
        await session.execute(
            insert(IntelRelation)
            .values(id=uuid.uuid4(), tenant_id=tenant_id, src_id=entity.id, dst_id=other.id, kind=hint.kind, source=key)
            .on_conflict_do_nothing(constraint="uq_intel_relation")
        )


# ---- sightings -----------------------------------------------------------------------------------------
_SIGHTING_FIELDS: dict[str, list[str]] = {
    "ip": ["network.dst_ip", "network.src_ip", "auth.source_ip", "host.ip", "dns.answers"],
    "domain": ["dns.question", "network.dst_domain"],
    "md5": ["process.hash.md5", "file.hash.md5"],
    "sha1": ["process.hash.sha1", "file.hash.sha1"],
    "sha256": ["process.hash.sha256", "file.hash.sha256"],
}


async def sightings(backend: SearchBackend, tenant_id: uuid.UUID, entity: IntelEntity, days: int) -> dict[str, Any]:
    end = datetime.now(UTC)
    tr = TimeRange(start=end - timedelta(days=days), end=end)
    by_field: dict[str, int] = {}
    hits: dict[str, dict[str, Any]] = {}
    hosts: dict[str, int] = {}
    if entity.type in _SIGHTING_FIELDS:
        for f in _SIGHTING_FIELDS[entity.type]:
            q = EventQuery(
                time_range=tr,
                limit=10,
                filters=[Filter(field=f, op="eq", value=entity.value)],
                aggregations=[Aggregation(name="h", type="terms", field="host.hostname", size=20)],
            )
            res = await backend.search(tenant_id, q)
            if res.total:
                by_field[f] = res.total
            hits.update({h["id"]: h for h in res.hits})
            for b in res.aggregations["h"].buckets:
                hosts[str(b.key)] = hosts.get(str(b.key), 0) + b.count
    elif entity.type in ("url", "email"):
        phrase = entity.value.replace('"', " ")
        q = EventQuery(
            time_range=tr,
            limit=10,
            q=f'"{phrase}"',
            aggregations=[Aggregation(name="h", type="terms", field="host.hostname", size=20)],
        )
        res = await backend.search(tenant_id, q)
        if res.total:
            by_field["free_text"] = res.total
        hits.update({h["id"]: h for h in res.hits})
        hosts = {str(b.key): b.count for b in res.aggregations["h"].buckets}
    recent = sorted(hits.values(), key=lambda h: h["timestamp"], reverse=True)[:10]
    return {
        "total": sum(by_field.values()),
        "by_field": by_field,
        "days": days,
        "hosts": [{"key": k, "count": c} for k, c in sorted(hosts.items(), key=lambda kv: -kv[1])[:10]],
        "first_seen": min((h["timestamp"] for h in hits.values()), default=None),
        "last_seen": max((h["timestamp"] for h in hits.values()), default=None),
        "recent": recent,
    }


# ---- STIX / TAXII import ---------------------------------------------------------------------------------
async def import_stix(
    session: AsyncSession, tenant_id: uuid.UUID, user_id: uuid.UUID | None, objects: list[Any], source: str
) -> dict[str, int]:
    parsed = stix_lib.parse(objects)
    ent_by_stix: dict[str, IntelEntity] = {}
    created = updated = 0
    for ind in parsed.indicators:
        existing = (
            await session.execute(
                select(IntelEntity.id).where(
                    IntelEntity.tenant_id == tenant_id, IntelEntity.type == ind.type, IntelEntity.value == ind.value
                )
            )
        ).first()
        entity = await upsert_entity(session, tenant_id, ind.type, ind.value, source="import", user_id=user_id)
        created, updated = (created + 1, updated) if existing is None else (created, updated + 1)
        # Never downgrade an analyst's explicit decision with a feed's opinion.
        if entity.watch_verdict is None:
            entity.watch_verdict, entity.watch_confidence = ind.verdict, ind.confidence
        entity.tags = sorted({*entity.tags, *ind.labels, f"feed:{source}"})[:20]
        await rescore(session, entity)
        ent_by_stix.setdefault(ind.stix_id, entity)
    for sid, type_, name in parsed.named:
        ent_by_stix[sid] = await upsert_entity(session, tenant_id, type_, name, source="import", user_id=user_id)
    relations = 0
    for src, dst, kind in parsed.relations:
        a, b = ent_by_stix.get(src), ent_by_stix.get(dst)
        if a and b and a.id != b.id:
            await session.execute(
                insert(IntelRelation)
                .values(id=uuid.uuid4(), tenant_id=tenant_id, src_id=a.id, dst_id=b.id, kind=kind, source=source)
                .on_conflict_do_nothing(constraint="uq_intel_relation")
            )
            relations += 1
    return {
        "created": created,
        "updated": updated,
        "named_objects": len(parsed.named),
        "relations": relations,
        "skipped": parsed.skipped,
    }
