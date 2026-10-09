"""Author's check: `python -m app.ai.playbooks.check` validates every playbook file and reports which upstream skills are still uncovered.
Unlike `catalog()` (which skips broken files so the app never fails to start) this prints every problem."""

import sys
from pathlib import Path

import yaml
from pydantic import ValidationError

from app.ai.playbooks import DATA, Playbook

UPSTREAM = Path(__file__).resolve().parents[3] / "tests" / "playbook_upstream_sources.txt"


def main() -> int:
    bad = 0
    covered: dict[str, list[str]] = {}
    ids: set[str] = set()
    files = sorted(DATA.glob("*.yaml"))
    for f in files:
        try:
            pb = Playbook.model_validate(yaml.safe_load(f.read_text(encoding="utf-8")))
            if pb.id != f.stem:
                raise ValueError(f"id {pb.id!r} must equal the file name {f.stem!r}")
            if pb.id in ids:
                raise ValueError("duplicate id")
            ids.add(pb.id)
            for s in pb.sources:
                covered.setdefault(s, []).append(pb.id)
            print(f"ok    {f.name}  ({len(pb.steps)} steps, {len(pb.model_dump_json())} chars)")
        except (ValidationError, ValueError, yaml.YAMLError) as exc:
            bad += 1
            print(f"FAIL  {f.name}")
            for line in str(exc).splitlines()[:12]:
                print("      " + line)
    upstream = [x for x in UPSTREAM.read_text().split() if x]
    invented = sorted(set(covered) - set(upstream))
    missing = [u for u in upstream if u not in covered]
    print(
        f"\n{len(files) - bad}/{len(files)} playbooks valid; {len(upstream) - len(missing)}/{len(upstream)} upstream skills covered"
    )
    if invented:
        bad += 1
        print("sources that are not upstream skill names (typo?):", ", ".join(invented))
    if missing:
        print("not covered yet:", ", ".join(missing))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
