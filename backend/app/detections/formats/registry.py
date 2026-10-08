from app.detections.formats.base import DetectionFormat
from app.detections.formats.query import HuntQueryFormat
from app.detections.formats.sigma import SigmaFormat

FORMATS: dict[str, DetectionFormat] = {f.format_id: f for f in (SigmaFormat(), HuntQueryFormat())}


def get(format_id: str) -> DetectionFormat:
    try:
        return FORMATS[format_id]
    except KeyError:
        raise KeyError(format_id) from None
