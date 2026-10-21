# ruff: noqa: E501
"""A stand-in for the LogRhythm Web Console client in the tests that are about WHAT is searched (planning, attribution, halving, sweeps...)
and not about the console protocol (that is tests/test_logrhythm_console.py, which drives the real client over a fake socket).

`install(monkeypatch, handler)` makes `LogRhythmConnector._console()` return a client that answers a console search by asking `handler`, the
same httpx handler these tests always used to imitate the SIEM: a `search-task` request carrying the query filter, then `search-result` pages.
So `make_siem`, `empty_siem` and the inline handlers keep describing "what the SIEM holds" in one place."""

import json
from datetime import datetime
from typing import Any

import httpx

from app.connectors._http import SourceError
from app.connectors.logrhythm import MAX_MSGS, LogRhythmConnector
from app.connectors.logrhythm_console import SearchOutcome

BASE = "https://lr.example/lr-search-api/actions"


class FakeConsole:
    def __init__(self, handler: Any) -> None:
        self.handler = handler
        self.searches: list[dict[str, Any]] = []  # every query filter asked, in order

    def _ask(self, endpoint: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = self.handler(httpx.Request("POST", f"{BASE}/{endpoint}", json=body))
        if resp.status_code in (401, 403):
            raise SourceError(f"authentication rejected (HTTP {resp.status_code}); check the credential and its role")
        if resp.status_code >= 400:
            raise SourceError(f"HTTP {resp.status_code}")
        out = json.loads(resp.content)
        if not isinstance(out, dict):
            raise SourceError("unexpected response shape")
        return out

    async def ping(self) -> str:
        return "console reachable, login accepted, socket open"

    async def run_search(
        self,
        query_filter: dict[str, Any],
        start: datetime,
        end: datetime,
        *,
        max_logs: int | None = None,
        deadline: float | None = None,
    ) -> SearchOutcome:
        self.searches.append(query_filter)
        body = {
            "maxMsgsToQuery": MAX_MSGS,
            "queryFilter": query_filter,
            "dateCriteria": {"dateMin": start.isoformat(), "dateMax": end.isoformat()},
        }
        task = self._ask("search-task", body)
        guid = task.get("TaskId") or task.get("taskId")
        if not guid:
            raise SourceError("search-task returned no TaskId")
        items: list[dict[str, Any]] = []
        status = "Completed"
        for _ in range(600):
            page = self._ask(
                "search-result",
                {"data": {"searchGuid": guid, "paginator": {"origin": len(items), "page_size": 500}}},
            )
            status = str(page.get("TaskStatus") or page.get("taskStatus") or "unknown")
            got = [i for i in (page.get("Items") or page.get("items") or []) if isinstance(i, dict)]
            if not got:
                break
            items += got
        if "Failed" in status or "Cancel" in status:
            return SearchOutcome([], "Search Failed", 0, False)
        if "Max Results" in status:
            final = "Completed: Max Results"
        else:
            final = "Completed: All Results" if items else "Completed: No Results"
        capped = max_logs is not None and len(items) > max_logs
        logs = items[:max_logs] if max_logs is not None else items
        return SearchOutcome(logs, final, len(items), capped or "Max Results" in status)


def install(monkeypatch: Any, handler: Any) -> FakeConsole:
    fake = FakeConsole(handler)
    monkeypatch.setattr(LogRhythmConnector, "_console", lambda self: fake)
    return fake
