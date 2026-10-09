"""Run every playbook query against the live telemetry (read-only) and report hit counts, so queries that parse but
match nothing because of how this tenant's data is shaped can be found and fixed.

    python scripts/playbook_smoke.py [tenant-name-substring]   (DATABASE_URL / OPENSEARCH_URL in the environment)

A query with 0 hits is not necessarily wrong (the technique may simply not be present) - but a playbook whose every
query is 0 while its `needs` telemetry exists deserves a look."""

import asyncio
import sys
from datetime import timedelta

from sqlalchemy import select

from app.ai import playbooks
from app.core.config import get_settings
from app.core.db import create_engine, create_sessionmaker
from app.events.search.base import SearchBackend
from app.events.search.opensearch import OpenSearchBackend
from app.events.search.query import Aggregation, EventQuery, TimeRange
from app.tenants.models import Tenant


async def main(match: str) -> None:
    settings = get_settings()
    from opensearchpy import AsyncOpenSearch

    client = AsyncOpenSearch(hosts=[settings.opensearch_url])
    backend: SearchBackend = OpenSearchBackend(client, settings)
    maker = create_sessionmaker(create_engine(settings))
    async with maker() as s:
        tenants = (await s.execute(select(Tenant))).scalars().all()
    tenant = next((t for t in tenants if match.lower() in t.name.lower()), tenants[0])
    print(f"tenant: {tenant.name}\n")
    tr = TimeRange.last(timedelta(days=365))
    zero_everywhere: list[str] = []
    for pb in playbooks.catalog().values():
        row = []
        for i, step in enumerate(pb.steps, 1):
            if step.tool not in ("search_events", "aggregate_events") or not step.query:
                continue
            from app.events.search import dsl

            text, filters = dsl.parse(step.query)
            aggs = [Aggregation(name="top", type="terms", field=step.field, size=3)] if step.field else []
            try:
                res = await backend.search(
                    tenant.id, EventQuery(q=text, filters=filters, time_range=tr, limit=1, aggregations=aggs)
                )
                row.append((i, res.total))
            except Exception as exc:  # noqa: BLE001
                row.append((i, f"ERR {type(exc).__name__}"))
        hits = [t for _, t in row if isinstance(t, int)]
        flag = "  <-- all zero" if hits and not any(hits) else ""
        if flag:
            zero_everywhere.append(pb.id)
        print(f"{pb.id:55s} needs={','.join(pb.needs):28s} " + " ".join(f"s{i}={t}" for i, t in row) + flag)
    print(f"\n{len(zero_everywhere)} playbook(s) with every query at 0 hits in 365d")
    await client.close()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else ""))
