from typing import Any

from pydantic import ValidationError

from app.connectors.base import Connector, NormalizationError
from app.events.schema import EventIn


class CanonicalConnector(Connector):
    """Pass-through for senders that already speak the canonical schema."""

    connector_type = "canonical"
    display_name = "Canonical JSON"

    def normalize(self, raw: dict[str, Any]) -> list[EventIn]:
        try:
            return [EventIn.model_validate(raw)]
        except ValidationError as exc:
            raise NormalizationError(_summarize(exc)) from None


def _summarize(exc: ValidationError) -> str:
    first = exc.errors()[0]
    return f"{'.'.join(str(p) for p in first['loc'])}: {first['msg']}"[:300]
