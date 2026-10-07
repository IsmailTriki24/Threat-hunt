import json

import pytest
from sqlalchemy import func, select

from app.mitre import data
from app.mitre.loader import import_stix_bundle, load_builtin, parse_stix_bundle
from app.mitre.models import MitreTactic, MitreTechnique


def test_builtin_dataset_is_well_formed():
    ids = [t[0] for t in data.TECHNIQUES]
    assert len(ids) == len(set(ids)) and len(ids) >= 65
    shortnames = {t[1] for t in data.TACTICS}
    assert len(data.TACTICS) == 14
    for tid, name, tactics, desc in data.TECHNIQUES:
        assert name and desc and tactics and set(tactics) <= shortnames, tid
        if "." in tid:
            assert tid.split(".")[0] in ids, f"{tid} has no parent"
    for known in ["T1059.001", "T1003.001", "T1053.005", "T1021.002", "T1110.003", "T1218.011", "T1568.002"]:
        assert known in ids


async def test_load_builtin_is_idempotent(app):
    async with app.state.sessionmaker() as s:
        first = await load_builtin(s)
        await s.commit()
    async with app.state.sessionmaker() as s:
        second = await load_builtin(s)
        await s.commit()
        n_t = (await s.execute(select(func.count()).select_from(MitreTechnique))).scalar_one()
        n_tac = (await s.execute(select(func.count()).select_from(MitreTactic))).scalar_one()
        sub = await s.get(MitreTechnique, "T1059.001")
    assert first == second == (14, len(data.TECHNIQUES))
    assert n_t >= len(data.TECHNIQUES) and n_tac >= 14
    assert sub.parent_id == "T1059" and sub.tactics == ["execution"] and sub.url.endswith("/T1059/001")


def _bundle():
    def ref(i):
        return [
            {
                "source_name": "mitre-attack",
                "external_id": i,
                "url": f"https://attack.mitre.org/techniques/{i.replace('.', '/')}",
            }
        ]

    phase = lambda p: [{"kill_chain_name": "mitre-attack", "phase_name": p}]  # noqa: E731
    return {
        "type": "bundle",
        "objects": [
            {
                "type": "x-mitre-tactic",
                "name": "Execution",
                "x_mitre_shortname": "execution",
                "external_references": ref("TA0002"),
            },
            {
                "type": "attack-pattern",
                "name": "Parent",
                "external_references": ref("T9001"),
                "kill_chain_phases": phase("execution"),
                "description": "first line\nsecond line",
            },
            {
                "type": "attack-pattern",
                "name": "Child",
                "x_mitre_is_subtechnique": True,
                "external_references": ref("T9001.001"),
                "kill_chain_phases": phase("execution"),
            },
            {"type": "attack-pattern", "name": "Revoked", "revoked": True, "external_references": ref("T9002")},
            {
                "type": "attack-pattern",
                "name": "Deprecated",
                "x_mitre_deprecated": True,
                "external_references": ref("T9003"),
            },
            {
                "type": "attack-pattern",
                "name": "OrphanSub",
                "external_references": ref("T9004.001"),
                "kill_chain_phases": phase("execution"),
            },
            {"type": "attack-pattern", "name": "Bad id", "external_references": ref("not-an-id")},
            {"type": "attack-pattern", "name": "No ref"},
            {"type": "malware", "name": "ignored"},
            "garbage",
        ],
    }


def test_parse_stix_skips_revoked_deprecated_invalid_and_orphans():
    tactics, techniques = parse_stix_bundle(_bundle())
    assert [t[0] for t in tactics] == ["TA0002"]
    assert {t["id"] for t in techniques} == {"T9001", "T9001.001"}
    assert next(t for t in techniques if t["id"] == "T9001")["description"] == "first line"
    with pytest.raises(ValueError):
        parse_stix_bundle({"nope": 1})


async def test_import_stix_links_subtechniques_and_is_idempotent(app):
    raw = json.dumps(_bundle())
    for _ in range(2):
        async with app.state.sessionmaker() as s:
            assert await import_stix_bundle(s, raw) == (1, 2)
            await s.commit()
    async with app.state.sessionmaker() as s:
        child = await s.get(MitreTechnique, "T9001.001")
        assert child.parent_id == "T9001" and child.source == "mitre-attack-stix"
        assert await s.get(MitreTechnique, "T9002") is None
