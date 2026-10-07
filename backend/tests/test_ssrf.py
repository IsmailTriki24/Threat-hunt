import httpx
import pytest

from app.core import ssrf


def resolver(mapping):
    async def _r(host, port):
        if host not in mapping:
            raise OSError("nxdomain")
        return mapping[host]

    return _r


@pytest.mark.parametrize(
    "addr",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.3.4",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",  # noqa: S104
        "100.64.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "224.0.0.1",
        "240.0.0.1",
    ],
)
def test_forbidden_addresses(addr):
    assert ssrf.is_forbidden_address(addr)


@pytest.mark.parametrize("addr", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_allowed(addr):
    assert not ssrf.is_forbidden_address(addr)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://x/",
        "ftp://example.com/",
        "http://user:pw@example.com/",
        "http:///x",
        "http://example.com:22/",
        "http://example.com:6379/",
        "http://localhost/",
        "http://internal.example/",
        "http://metadata.example/",
        "http://rebind.example/",
        "http://missing.example/",
        "http://example.com:99999/",
    ],
)
async def test_blocked_urls(url):
    r = resolver(
        {
            "localhost": ["127.0.0.1", "::1"],
            "internal.example": ["10.1.1.1"],
            "metadata.example": ["169.254.169.254"],
            "rebind.example": ["8.8.8.8", "127.0.0.1"],
            "example.com": ["93.184.216.34"],
        }
    )
    with pytest.raises(ssrf.SsrfError):
        await ssrf.validate_url(url, r)


async def test_allowed_url_returns_validated_addresses():
    host, port, addrs = await ssrf.validate_url(
        "https://api.example.com/x", resolver({"api.example.com": ["93.184.216.34"]})
    )
    assert (host, port, addrs) == ("api.example.com", 443, ["93.184.216.34"])


async def test_private_allowed_only_when_explicitly_enabled(monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "outbound_allow_private", True)
    await ssrf.validate_url("http://localhost/", resolver({"localhost": ["127.0.0.1"]}))


async def test_transport_pins_ip_and_preserves_host_header():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"], seen["host"], seen["sni"] = (
            str(request.url),
            request.headers["host"],
            request.extensions.get("sni_hostname"),
        )
        return httpx.Response(200, json={"ok": True})

    r = await ssrf.fetch(
        "GET",
        "https://api.example.com/v1?a=1",
        transport=httpx.MockTransport(handler),
        resolver=resolver({"api.example.com": ["93.184.216.34"]}),
    )
    assert r.json() == {"ok": True}
    assert (
        seen["url"].startswith("https://93.184.216.34/v1")
        and seen["host"] == "api.example.com"
        and seen["sni"] == "api.example.com"
    )


async def test_redirect_to_private_address_is_blocked_and_credentials_stripped():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.headers.get("authorization"))
        if request.headers["host"] == "a.example.com":
            return httpx.Response(302, headers={"location": "http://evil.example.com/next"})
        return httpx.Response(200, text="should not be reached for internal")

    res = resolver(
        {"a.example.com": ["93.184.216.34"], "evil.example.com": ["8.8.4.4"], "int.example.com": ["10.0.0.1"]}
    )
    r = await ssrf.fetch(
        "GET",
        "http://a.example.com/",
        headers={"Authorization": "Bearer s3cret"},
        transport=httpx.MockTransport(handler),
        resolver=res,
    )
    assert r.status_code == 200 and calls == ["Bearer s3cret", None]  # credential not forwarded cross-host

    def to_internal(request: httpx.Request) -> httpx.Response:
        return httpx.Response(307, headers={"location": "http://int.example.com/admin"})

    with pytest.raises(ssrf.SsrfError):
        await ssrf.fetch("GET", "http://a.example.com/", transport=httpx.MockTransport(to_internal), resolver=res)


async def test_redirect_loop_and_oversized_response_are_bounded(monkeypatch):
    res = resolver({"a.example.com": ["93.184.216.34"]})
    loop = httpx.MockTransport(lambda r: httpx.Response(302, headers={"location": "/again"}))
    with pytest.raises(ssrf.SsrfError, match="redirects"):
        await ssrf.fetch("GET", "http://a.example.com/", transport=loop, resolver=res)
    monkeypatch.setattr(ssrf, "MAX_RESPONSE_BYTES", 100)
    big = httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 1000))
    with pytest.raises(ssrf.SsrfError, match="too large"):
        await ssrf.fetch("GET", "http://a.example.com/", transport=big, resolver=res)
