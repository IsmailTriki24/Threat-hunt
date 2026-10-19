# ruff: noqa: E501
"""LogRhythm Admin API (same :8501 gateway and token): the entities and log source types a search can be narrowed to.

Verified on a production 7.9 (2026-10-19): `GET /lr-admin-api/entities/` lists the entities the token can see;
`GET /lr-admin-api/logsources?count=N` lists the log sources (the default page is 100; `count=1000` returned all 786), each with its
`logSourceType {id, name}` and `entity {id, name}`. The ids are the ones the Search API's Entity (6) and MsgSourceType (9) filters take."""

from typing import Any

from app.connectors._http import SourceError
from app.connectors.logrhythm_alarms import _get

PAGE = 1000  # count=5000 is refused (HTTP 400); count=1000 returned all 786 log sources
MAX_PAGES = 10


async def search_scopes(connector: Any) -> dict[str, list[dict[str, Any]]]:
    """{"entities": [{id, name}], "source_types": [{id, name, sources}]} - what a browse can be narrowed to, sorted by name."""
    entities = await _get(connector, "entities/", api="lr-admin-api")
    sources: dict[Any, Any] = {}
    for page_no in range(MAX_PAGES):
        page = await _get(connector, "logsources", {"count": PAGE, "offset": page_no * PAGE}, api="lr-admin-api")
        if not isinstance(page, list):
            raise SourceError("unexpected admin response shape")
        fresh = {s.get("id"): s for s in page if isinstance(s, dict) and s.get("id") not in sources}
        sources.update(fresh)
        if (
            len(page) < PAGE or not fresh
        ):  # a short page is the last; a page of only known sources means the offset is ignored
            break
    if not isinstance(entities, list):
        raise SourceError("unexpected admin response shape")
    ents = {
        int(e["id"]): {"id": int(e["id"]), "name": str(e.get("fullName") or e.get("name") or e["id"])[:128]}
        for e in entities
        if isinstance(e, dict) and isinstance(e.get("id"), int) and e.get("recordStatusName", "Active") == "Active"
    }
    types: dict[int, dict[str, Any]] = {}
    for s in sources.values():
        t = s.get("logSourceType") if isinstance(s, dict) else None
        if isinstance(t, dict) and isinstance(t.get("id"), int):
            row = types.setdefault(t["id"], {"id": t["id"], "name": str(t.get("name") or t["id"])[:128], "sources": 0})
            row["sources"] += 1
    return {
        "entities": sorted(ents.values(), key=lambda r: r["name"].lower()),
        "source_types": sorted(types.values(), key=lambda r: r["name"].lower()),
    }
