"""Web search for the hunt agent (Tavily). The only AI tool that talks to the public internet, so it is narrow by design: one fixed,
operator-configured endpoint; no URL fetching; short snippets only. What it returns is untrusted third-party text."""

from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.config import Settings

TIMEOUT_S = 15.0
SNIPPET_CHARS = 600


class WebSearchError(Exception):
    """Safe to show to the model: never contains the key or the upstream body."""

    def __init__(self, message: str, transient: bool = False) -> None:
        super().__init__(message)
        self.transient = transient


async def search(
    settings: Settings,
    query: str,
    max_results: int = 5,
    *,
    include_domains: list[str] | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[dict[str, Any]]:
    if not settings.tavily_api_key:
        raise WebSearchError("web search is not configured")
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_S, transport=transport, follow_redirects=False) as client:
            resp = await client.post(
                f"{settings.tavily_base_url.rstrip('/')}/search",
                headers={"Authorization": f"Bearer {settings.tavily_api_key}"},
                json={
                    **({"include_domains": include_domains} if include_domains else {}),
                    "query": query,
                    "max_results": max_results,
                    "search_depth": "basic",
                    "include_answer": False,
                    "include_raw_content": False,
                    "include_images": False,
                },
            )
    except httpx.TimeoutException:
        raise WebSearchError("the web search timed out", transient=True) from None
    except httpx.HTTPError:
        raise WebSearchError("the web search service is unreachable", transient=True) from None
    if resp.status_code in (401, 403):
        raise WebSearchError("web search credentials were rejected by the provider")
    if resp.status_code == 429 or resp.status_code >= 500:
        raise WebSearchError("the web search service is busy", transient=True)
    if resp.status_code >= 400:
        raise WebSearchError(f"the web search service rejected the request ({resp.status_code})")
    try:
        raw = resp.json().get("results") or []
    except ValueError:
        raise WebSearchError("the web search service returned an unreadable response", transient=True) from None
    out: list[dict[str, Any]] = []
    for r in raw[:max_results]:
        url = str(r.get("url") or "")
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            continue
        out.append(
            {
                "title": " ".join(str(r.get("title") or "").split())[:160],
                "url": url[:300],
                "domain": parsed.hostname,
                "snippet": " ".join(str(r.get("content") or "").split())[:SNIPPET_CHARS],
                "score": round(float(r["score"]), 2) if isinstance(r.get("score"), int | float) else None,
            }
        )
    return out
