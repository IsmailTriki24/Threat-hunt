from typing import Any

from pydantic import BaseModel, Field, ValidationError

from app.connectors.base import Connector, NormalizationError
from app.connectors.canonical import _summarize
from app.events.schema import EventIn


class GenericJsonConfig(BaseModel):
    """Maps canonical dotted field names to dotted paths in the raw record, e.g.
    {"timestamp": "ts", "host.hostname": "device.name", "process.command_line": "cmd"}."""

    field_map: dict[str, str] = Field(default_factory=dict, max_length=64)
    source: str = "generic_json"
    default_event_type: str = "other"
    keep_raw: bool = True


def _dig(obj: Any, path: str) -> Any:
    for part in path.split("."):
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        else:
            return None
    return obj


class GenericJsonConnector(Connector):
    connector_type = "generic_json"
    display_name = "Generic JSON"
    config_model = GenericJsonConfig

    def normalize(self, raw: dict[str, Any]) -> list[EventIn]:
        cfg: GenericJsonConfig = self.config  # type: ignore[assignment]
        doc: dict[str, Any] = {"source": cfg.source, "event_type": cfg.default_event_type}
        for target, source_path in cfg.field_map.items():
            value = _dig(raw, source_path)
            if value is None:
                continue
            node = doc
            *parents, leaf = target.split(".")
            for part in parents:
                node = node.setdefault(part, {})
            node[leaf] = value
        if "timestamp" not in doc:
            raise NormalizationError("timestamp: no value found via field_map")
        if cfg.keep_raw:
            doc["raw"] = raw
        try:
            return [EventIn.model_validate(doc)]  # unknown target fields are rejected (extra=forbid)
        except ValidationError as exc:
            raise NormalizationError(_summarize(exc)) from None
