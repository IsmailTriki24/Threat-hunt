from pydantic import BaseModel

from app.connectors.base import Connector
from app.connectors.canonical import CanonicalConnector
from app.connectors.generic_json import GenericJsonConnector
from app.connectors.generic_rest import GenericRestConnector
from app.connectors.logrhythm import LogRhythmConnector
from app.connectors.suricata import SuricataConnector
from app.connectors.sysmon import SysmonConnector
from app.connectors.trend_vision_one import TrendVisionOneConnector
from app.connectors.wazuh import WazuhConnector
from app.connectors.windows_eventlog import WindowsEventLogConnector
from app.connectors.zeek import ZeekConnector

_REGISTRY: dict[str, type[Connector]] = {}


def register(cls: type[Connector]) -> type[Connector]:
    _REGISTRY[cls.connector_type] = cls
    return cls


for _cls in (
    CanonicalConnector,
    GenericJsonConnector,
    GenericRestConnector,
    SysmonConnector,
    ZeekConnector,
    SuricataConnector,
    WazuhConnector,
    WindowsEventLogConnector,
    LogRhythmConnector,
    TrendVisionOneConnector,
):
    register(_cls)


def available() -> list[str]:
    return sorted(_REGISTRY)


def build(type_: str, config: dict[str, object] | None = None, secrets: dict[str, str] | None = None) -> Connector:
    cls = _REGISTRY.get(type_)
    if cls is None:
        raise KeyError(type_)
    cfg: BaseModel = cls.config_model.model_validate(config or {})
    return cls(cfg, secrets)
