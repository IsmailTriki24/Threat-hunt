"""Built-in SIEM behaviours (`iochunt/siem_behaviours.py`) appear as ordinary detection rules so their alerts live on the Detections page.
They run inside the SIEM (the sweep), not over stored events, so this format is never executable here and is hidden from the format list."""

from typing import ClassVar

from app.detections.formats.base import DetectionFormat, ParsedRule


class SiemFormat(DetectionFormat):
    format_id = "siem"
    display_name = "Built-in SIEM behaviour"
    description = "Runs inside the connected SIEM; managed by the platform."
    hidden: ClassVar[bool] = True

    def parse(self, content: str) -> ParsedRule:
        title = (content.strip().splitlines() or ["Built-in SIEM behaviour"])[0].removeprefix("built-in:").strip()
        return ParsedRule(
            title=title[:200], unsupported=["This behaviour runs inside the SIEM and is managed by the platform"]
        )
