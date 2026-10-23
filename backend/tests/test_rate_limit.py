"""A source that answers 429 is waited on briefly, remembered, and reported; it never holds a search for minutes."""

import time
from datetime import timedelta

import httpx
import pytest

from app.auth.rbac import Role
from app.connectors import _http, registry
from tests.test_siem_connectors import EP_BASE, NOW, _resolve, get_settings_with_ports

URL = "https://api.eu.xdr.trendmicro.com/v3.0/search/endpointActivities"


@pytest.fixture
def upstream(monkeypatch):
    """Serve `handler` for connector HTTP. Returns (requests seen, sleeps asked for)."""
    seen: list[httpx.Request] = []
    slept: list[float] = []

    def install(handler):
        def wrapped(request):
            seen.append(request)
            return handler(request)

        monkeypatch.setattr(_http, "HTTP_TRANSPORT", httpx.MockTransport(wrapped))
        monkeypatch.setattr(_http, "RESOLVER", _resolve)
        monkeypatch.setattr("app.core.ssrf.get_settings", get_settings_with_ports)

    async def sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr("app.connectors._http.asyncio.sleep", sleep)
    _http.reset_cooldowns()
    yield install, seen, slept
    _http.reset_cooldowns()


async def _get(key="KEY-A", url=URL):
    return await _http.request_json("GET", url, headers={"Authorization": f"Bearer {key}"}, params={"top": 1})


async def test_a_long_retry_after_is_reported_at_once_not_slept_through(upstream):
    install, seen, slept = upstream
    install(lambda r: httpx.Response(429, headers={"retry-after": "60"}))
    with pytest.raises(_http.RateLimited) as exc:
        await _get()
    assert len(seen) == 1 and slept == []
    assert 59 < exc.value.retry_in_s <= 60 and "try again in about 60 s" in str(exc.value)
    assert isinstance(exc.value, _http.SourceError)  # every caller that reports a failed source reports this too


async def test_the_cooldown_stops_every_later_call_for_that_key_and_endpoint_only(upstream):
    install, seen, _ = upstream
    install(
        lambda r: (
            httpx.Response(429, headers={"retry-after": "60"})
            if "KEY-A" in r.headers["authorization"] and r.url.path.endswith("endpointActivities")
            else httpx.Response(200, json={"ok": 1})
        )
    )
    with pytest.raises(_http.RateLimited):
        await _get("KEY-A")
    sent = len(seen)
    with pytest.raises(_http.RateLimited):
        await _get("KEY-A")
    assert len(seen) == sent  # the second call never left the process
    assert (await _get("KEY-B")) == {"ok": 1}  # another credential has its own quota
    assert (await _get("KEY-A", url=URL.replace("endpointActivities", "detections"))) == {
        "ok": 1
    }  # and so does another endpoint


async def test_the_cooldown_ends(upstream):
    install, seen, _ = upstream
    answers = iter([httpx.Response(429, headers={"retry-after": "60"}), httpx.Response(200, json={"ok": 1})])
    install(lambda r: next(answers))
    with pytest.raises(_http.RateLimited):
        await _get()
    for key in list(_http._cooldowns):
        _http._cooldowns[key] = time.monotonic() - 1
    assert await _get() == {"ok": 1}


async def test_a_short_retry_after_is_waited_out_and_retried(upstream):
    install, seen, slept = upstream
    answers = iter([httpx.Response(429, headers={"retry-after": "2"}), httpx.Response(200, json={"ok": 1})])
    install(lambda r: next(answers))
    assert await _get() == {"ok": 1}
    assert len(seen) == 2 and slept and 0 < slept[0] <= 2


async def test_a_background_job_can_afford_to_wait_longer(upstream):
    install, seen, slept = upstream
    answers = iter([httpx.Response(429, headers={"retry-after": "30"}), httpx.Response(200, json={"ok": 1})])
    install(lambda r: next(answers))
    with _http.patience(90):
        assert await _get() == {"ok": 1}
    assert len(seen) == 2 and slept and 25 < slept[0] <= 30
    assert _http.THROTTLE_PATIENCE_S.get() == 5.0  # back to the short default outside the block


async def test_a_429_without_retry_after_backs_off_a_little_then_reports(upstream):
    install, seen, slept = upstream
    install(lambda r: httpx.Response(429))
    with pytest.raises(_http.RateLimited):
        await _get()
    assert (
        len(seen) == 4 and max(slept) <= 5
    )  # 1 s, 2 s, 4 s: each wait within the patience; the fourth answer's 8 s is reported, not slept


async def test_the_credential_never_appears_in_the_key_or_the_message(upstream):
    install, _, _ = upstream
    install(lambda r: httpx.Response(429, headers={"retry-after": "60"}))
    with pytest.raises(_http.RateLimited) as exc:
        await _get("SECRET-KEY-VALUE")
    assert "SECRET-KEY-VALUE" not in str(exc.value) and not any("SECRET-KEY-VALUE" in k for k in _http._cooldowns)


async def test_a_throttled_trend_search_fails_fast_with_the_reason(upstream):
    install, seen, slept = upstream
    install(lambda r: httpx.Response(429, headers={"retry-after": "60"}))
    conn = registry.build("trend_vision_one", {"dataset": "endpoint_activity"}, {"api_key": "KEY-123"})
    with pytest.raises(_http.RateLimited, match="rate-limiting requests"):
        await conn.search_query("45.198.224.169", NOW - timedelta(hours=1), NOW)
    assert len(seen) == 1 and slept == []


async def test_collection_keeps_the_windows_it_read_when_the_source_throttles(client, make, app, upstream):
    install, seen, _ = upstream
    t = await make.tenant()
    _, h = await make.login_as(t, Role.SUPER_ADMIN)

    def handler(request):
        if len(seen) <= 2:  # the first two 3-minute windows are served, then Trend says wait
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            **EP_BASE,
                            "uuid": f"w{len(seen)}",
                            "eventId": "1",
                            "objectName": "x.exe",
                            "objectCmd": "x.exe /a",
                        }
                    ]
                },
            )
        return httpx.Response(429, headers={"retry-after": "60"})

    install(handler)
    ds = (
        await client.post(
            "/api/v1/data-sources",
            headers=h,
            json={
                "name": "TM",
                "connector_type": "trend_vision_one",
                "config": {"dataset": "endpoint_activity"},
                "secrets": {"api_key": "key-VALUE-2"},
            },
        )
    ).json()
    assert (await client.post(f"/api/v1/data-sources/{ds['id']}/collect", headers=h)).status_code == 200
    row = next(d for d in (await client.get("/api/v1/data-sources", headers=h)).json() if d["id"] == ds["id"])
    assert row["health_status"] == "degraded" and "rate-limiting" in row["health_detail"]
    assert "resumes on its own" in row["health_detail"] and row["events_total"] == 2
    again = len(seen)
    await client.post(f"/api/v1/data-sources/{ds['id']}/collect", headers=h)  # still cooling down: no request is sent
    assert len(seen) == again
