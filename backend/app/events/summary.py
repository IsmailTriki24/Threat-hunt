"""One-line human summaries derived purely from event fields (used by timelines and evidence snapshots)."""

from typing import Any


def _g(doc: dict[str, Any], *path: str) -> Any:
    for p in path:
        if not isinstance(doc, dict):
            return None
        doc = doc.get(p)  # type: ignore[assignment]
    return doc


def summarize(doc: dict[str, Any]) -> str:
    etype = doc.get("event_type")
    proc = _g(doc, "process", "name") or "process"
    if etype == "process_creation":
        parent = _g(doc, "process", "parent", "name")
        return f"{proc} started" + (f" by {parent}" if parent else "")
    if etype == "network_connection":
        dst = _g(doc, "network", "dst_domain") or _g(doc, "network", "dst_ip") or "unknown"
        port = _g(doc, "network", "dst_port")
        arrow = "←" if _g(doc, "network", "direction") == "inbound" else "→"
        return f"{proc} {arrow} {dst}" + (f":{port}" if port else "")
    if etype == "dns_query":
        return f"{proc} resolved {_g(doc, 'dns', 'question') or 'unknown'}"
    if etype == "file_event":
        target = _g(doc, "file", "path") or _g(doc, "file", "name") or "file"
        return f"{proc} {str(doc.get('action') or 'touched').replace('_', ' ')} {target}"
    if etype == "authentication":
        who = _g(doc, "user", "name") or "unknown user"
        how = _g(doc, "auth", "logon_type")
        src = _g(doc, "auth", "source_ip")
        return (
            f"{str(doc.get('action') or 'logon').replace('_', ' ')} ({doc.get('outcome', 'unknown')}) for {who}"
            + (f" [{how}]" if how else "")
            + (f" from {src}" if src else "")
        )
    return str(doc.get("message") or doc.get("action") or etype or "event")[:200]
