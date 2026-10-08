"""ATT&CK reference-data loading: built-in curated set and official STIX bundle import. Both are idempotent upserts."""

import json
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.mitre import data
from app.mitre.models import MitreSoftware, MitreTactic, MitreTechnique

_TECH_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_TACTIC_ID = re.compile(r"^TA\d{4}$")


async def _upsert_tactics(session: AsyncSession, rows: list[tuple[str, str, str, int]]) -> int:
    existing = {t.id: t for t in (await session.execute(select(MitreTactic))).scalars()}
    for tid, short, name, pos in rows:
        row = existing.get(tid)
        if row is None:
            session.add(MitreTactic(id=tid, shortname=short, name=name, position=pos))
        else:
            row.shortname, row.name, row.position = short, name, pos
    await session.flush()
    return len(rows)


async def _upsert_techniques(session: AsyncSession, rows: list[dict[str, Any]], source: str) -> int:
    existing = {t.id: t for t in (await session.execute(select(MitreTechnique))).scalars()}
    ordered = sorted(rows, key=lambda r: ("." in r["id"], r["id"]))  # parents before children
    for r in ordered:
        row = existing.get(r["id"])
        parent = r["id"].split(".")[0] if "." in r["id"] else None
        if row is None:
            session.add(
                MitreTechnique(
                    id=r["id"],
                    name=r["name"],
                    parent_id=parent,
                    tactics=r["tactics"],
                    description=r["description"],
                    url=r["url"],
                    source=source,
                )
            )
        else:
            row.name, row.parent_id, row.tactics = r["name"], parent, r["tactics"]
            row.description, row.url, row.source = r["description"], r["url"], source
        await session.flush()
    return len(ordered)


async def load_builtin(session: AsyncSession) -> tuple[int, int]:
    tactics = await _upsert_tactics(session, [(i, s, n, pos) for pos, (i, s, n) in enumerate(data.TACTICS)])
    techniques = await _upsert_techniques(
        session,
        [
            {"id": i, "name": n, "tactics": t, "description": d, "url": data.technique_url(i)}
            for i, n, t, d in data.TECHNIQUES
        ],
        data.BUILTIN_SOURCE,
    )
    return tactics, techniques


def _mitre_ref(obj: dict[str, Any]) -> tuple[str | None, str]:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"]), str(ref.get("url") or "")
    return None, ""


def parse_stix_bundle(bundle: dict[str, Any]) -> tuple[list[tuple[str, str, str, int]], list[dict[str, Any]]]:
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise ValueError("not a STIX bundle: missing 'objects' list")
    tactics: list[tuple[str, str, str, int]] = []
    techniques: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext_id, url = _mitre_ref(obj)
        if ext_id is None:
            continue
        if obj.get("type") == "x-mitre-tactic" and _TACTIC_ID.match(ext_id):
            tactics.append((ext_id, str(obj.get("x_mitre_shortname", "")), str(obj.get("name", ext_id))[:120], 0))
        elif obj.get("type") == "attack-pattern" and _TECH_ID.match(ext_id):
            phases = [
                p["phase_name"]
                for p in obj.get("kill_chain_phases") or []
                if isinstance(p, dict) and p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")
            ]
            techniques[ext_id] = {
                "id": ext_id,
                "name": str(obj.get("name", ext_id))[:200],
                "tactics": phases,
                "description": str(obj.get("description", "")).split("\n")[0][:500],
                "url": url[:300],
            }
    # keep sub-techniques only when their parent survived filtering
    kept = [t for t in techniques.values() if "." not in t["id"] or t["id"].split(".")[0] in techniques]
    order = {i: p for p, (i, _, _) in enumerate(data.TACTICS)}
    tactics.sort(key=lambda t: (order.get(t[0], 99), t[0]))
    return [(i, s, n, pos) for pos, (i, s, n, _) in enumerate(tactics)], kept


async def import_stix_bundle(session: AsyncSession, bundle: dict[str, Any] | str | bytes) -> tuple[int, int]:
    parsed = json.loads(bundle) if isinstance(bundle, str | bytes) else bundle
    tactics, techniques = parse_stix_bundle(parsed)
    n_tactics = await _upsert_tactics(session, tactics)
    n_tech = await _upsert_techniques(session, techniques, "mitre-attack-stix")
    await _upsert_software(session, parse_software(parsed))
    return n_tactics, n_tech


_CITATION = re.compile(r"\(Citation:[^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_SOFT_ID = re.compile(r"^(S\d{4}|G\d{4})$")


def alias_key(name: str) -> str:
    """Normalised alias for matching threat names: lower-case alphanumerics only ('Qak Bot' == 'qakbot' == 'QAKBOT')."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def parse_software(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Software (malware/tool) and groups with their documented techniques, from an ATT&CK STIX bundle."""
    objects = [
        o
        for o in bundle.get("objects", [])
        if isinstance(o, dict) and not o.get("revoked") and not o.get("x_mitre_deprecated")
    ]
    technique_by_stix: dict[str, str] = {}
    for o in objects:
        if o.get("type") == "attack-pattern":
            ext, _ = _mitre_ref(o)
            if ext and _TECH_ID.match(ext) and o.get("id"):
                technique_by_stix[str(o["id"])] = ext
    uses: dict[str, set[str]] = {}
    for o in objects:
        if (
            o.get("type") == "relationship"
            and o.get("relationship_type") == "uses"
            and str(o.get("target_ref", "")).startswith("attack-pattern--")
        ):
            t = technique_by_stix.get(str(o["target_ref"]))
            if t:
                uses.setdefault(str(o.get("source_ref")), set()).add(t)
    out: list[dict[str, Any]] = []
    for o in objects:
        kind = {"malware": "malware", "tool": "tool", "intrusion-set": "group"}.get(str(o.get("type")))
        if kind is None:
            continue
        ext, url = _mitre_ref(o)
        if not ext or not _SOFT_ID.match(ext) or not o.get("id"):
            continue
        name = str(o.get("name", ext))[:200]
        raw_aliases = o.get("x_mitre_aliases") or o.get("aliases") or []
        aliases = list(dict.fromkeys([name, *[str(a)[:200] for a in raw_aliases if isinstance(a, str)]]))[:30]
        desc = _MD_LINK.sub(r"\1", _CITATION.sub("", str(o.get("description", "")))).split("\n")[0].strip()[:1200]
        out.append(
            {
                "id": ext,
                "name": name,
                "kind": kind,
                "aliases": aliases,
                "alias_keys": sorted({alias_key(a) for a in aliases if alias_key(a)}),
                "description": desc,
                "technique_ids": sorted(uses.get(str(o["id"]), set())),
                "url": url[:300],
            }
        )
    return out


async def _upsert_software(session: AsyncSession, rows: list[dict[str, Any]]) -> int:
    existing = {r.id: r for r in (await session.execute(select(MitreSoftware))).scalars()}
    for r in rows:
        row = existing.get(r["id"])
        if row is None:
            session.add(MitreSoftware(**r))
        else:
            for k, v in r.items():
                setattr(row, k, v)
    await session.flush()
    return len(rows)
