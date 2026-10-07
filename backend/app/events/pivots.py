from typing import Any

from pydantic import BaseModel


class Pivot(BaseModel):
    label: str
    field: str
    value: str | int
    entity: str  # host | user | ip | domain | hash | process | file


# (label, field path, entity)
_PIVOTS: list[tuple[str, str, str]] = [
    ("Host", "host.hostname", "host"),
    ("User", "user.name", "user"),
    ("Process", "process.name", "process"),
    ("Parent process", "process.parent.name", "process"),
    ("Process SHA-256", "process.hash.sha256", "hash"),
    ("File SHA-256", "file.hash.sha256", "hash"),
    ("File name", "file.name", "file"),
    ("Source IP", "network.src_ip", "ip"),
    ("Destination IP", "network.dst_ip", "ip"),
    ("Destination domain", "network.dst_domain", "domain"),
    ("DNS question", "dns.question", "domain"),
    ("Auth source IP", "auth.source_ip", "ip"),
]


def _dig(doc: dict[str, Any], path: str) -> Any:
    for part in path.split("."):
        if not isinstance(doc, dict) or part not in doc:
            return None
        doc = doc[part]
    return doc


def pivots_for(doc: dict[str, Any]) -> list[Pivot]:
    out = [
        Pivot(label=label, field=path, value=v, entity=entity)
        for label, path, entity in _PIVOTS
        if isinstance(v := _dig(doc, path), str | int) and v != ""
    ]
    for ip in (doc.get("host") or {}).get("ip", []):
        out.append(Pivot(label="Host IP", field="host.ip", value=ip, entity="ip"))
    return out
