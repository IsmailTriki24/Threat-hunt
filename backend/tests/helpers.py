from datetime import UTC, datetime, timedelta
from typing import Any

from app.events.schema import EventIn


def ev(minutes_ago: float = 5, **overrides: Any) -> EventIn:
    doc: dict[str, Any] = {
        "timestamp": datetime.now(UTC) - timedelta(minutes=minutes_ago),
        "source": "sysmon",
        "event_type": "process_creation",
        "host": {"hostname": "WS-01", "ip": ["10.0.0.5"]},
        "user": {"name": "alice", "domain": "CORP"},
    }
    doc.update(overrides)
    return EventIn.model_validate(doc)
