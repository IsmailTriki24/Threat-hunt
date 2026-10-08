"""'Hunt query' detection format: the rule body is the analyst's hunt query language text (see events/search/dsl.py)."""

from app.detections.formats.base import DetectionFormat, ParsedRule, RuleError
from app.events.search.dsl import QueryParseError, parse
from app.events.search.query import Condition, Filter


class HuntQueryFormat(DetectionFormat):
    format_id = "hunt_query"
    display_name = "Hunt query"
    description = "A hunt query-language expression. Title and severity are taken from the first lines: `# title: …`, `# level: high`."

    def parse(self, content: str) -> ParsedRule:
        meta: dict[str, str] = {}
        body: list[str] = []
        for line in content.splitlines():
            if line.startswith("#") and ":" in line:
                k, _, v = line[1:].partition(":")
                meta[k.strip().lower()] = v.strip()
            else:
                body.append(line)
        text = " ".join(body).strip()
        if not meta.get("title"):
            raise RuleError("a '# title: …' header line is required")
        if not text:
            raise RuleError("the query is empty")
        try:
            q, filters = parse(text)
        except QueryParseError as exc:
            raise RuleError(f"query: {exc}") from None
        rule = ParsedRule(
            title=meta["title"][:200],
            description=meta.get("description", "")[:5000],
            severity=meta.get("level", "medium").upper()
            if meta.get("level", "medium").upper() in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
            else "MEDIUM",
        )
        if q:
            rule.unsupported.append("free-text terms are not supported in detections; use field filters")
            return rule
        if not filters:
            rule.unsupported.append("the query has no field filters")
            return rule
        rule.where = (
            Condition(all=[Condition(filter=f) for f in filters]) if len(filters) > 1 else Condition(filter=filters[0])
        )
        _ = Filter
        return rule
