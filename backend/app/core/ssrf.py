"""SSRF protection for every outbound request the platform makes on behalf of users or data.

Defence layers:
  1. Scheme allow-list (http/https) and port allow-list.
  2. The hostname is resolved *here* and every returned address must be a public unicast address;
     the connection is then made to that exact IP (pinned) with the original Host header and TLS SNI /
     certificate hostname, so DNS rebinding between check and use is not possible.
  3. Redirects are never followed implicitly; callers re-validate each hop (see `fetch`).
"""

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.core.config import get_settings

Resolver = Callable[[str, int], Awaitable[list[str]]]
MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 10 * 1024 * 1024


class SsrfError(ValueError):
    pass


def is_forbidden_address(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.ip_network("100.64.0.0/10"))  # CGNAT
    )


async def default_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(i[4][0]) for i in infos))


def allowed_ports() -> set[int]:
    return {int(p) for p in get_settings().outbound_allowed_ports.split(",") if p.strip().isdigit()}


async def validate_url(url: str, resolver: Resolver = default_resolver) -> tuple[str, int, list[str]]:
    """Returns (host, port, validated_addresses) or raises SsrfError."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SsrfError("only http and https URLs are allowed")
    if not parts.hostname or parts.username or parts.password:
        raise SsrfError("URL must have a host and no embedded credentials")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        raise SsrfError("invalid port") from None
    if port not in allowed_ports():
        raise SsrfError(f"port {port} is not allowed")
    try:
        addrs = await resolver(parts.hostname, port)
    except OSError:
        raise SsrfError("host cannot be resolved") from None
    if not addrs:
        raise SsrfError("host cannot be resolved")
    if not get_settings().outbound_allow_private:
        for a in addrs:
            if is_forbidden_address(a):
                raise SsrfError("destination address is not allowed")
    return parts.hostname, port, addrs


class SafeTransport(httpx.AsyncBaseTransport):
    """httpx transport that validates and pins the destination IP for every request."""

    def __init__(self, inner: httpx.AsyncBaseTransport | None = None, resolver: Resolver = default_resolver) -> None:
        self._inner = inner or httpx.AsyncHTTPTransport(retries=0)
        self._resolver = resolver

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host, _port, addrs = await validate_url(str(request.url), self._resolver)
        ip = addrs[0]
        pinned_host = f"[{ip}]" if ":" in ip else ip
        headers = httpx.Headers(request.headers)
        headers["Host"] = request.headers.get("host", host)
        extensions: dict[str, Any] = {**request.extensions, "sni_hostname": host}
        pinned = httpx.Request(
            request.method,
            request.url.copy_with(host=pinned_host),
            headers=headers,
            stream=request.stream,
            extensions=extensions,
        )
        return await self._inner.handle_async_request(pinned)

    async def aclose(self) -> None:
        await self._inner.aclose()


async def fetch(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, Any] | None = None,
    timeout_s: float = 15.0,
    transport: httpx.AsyncBaseTransport | None = None,
    resolver: Resolver = default_resolver,
) -> httpx.Response:
    """SSRF-safe single-shot HTTP request with manual, re-validated redirects and a response size cap."""
    safe = SafeTransport(transport, resolver)
    async with httpx.AsyncClient(transport=safe, timeout=timeout_s, follow_redirects=False) as client:
        for _ in range(MAX_REDIRECTS + 1):
            req = client.build_request(method, url, headers=headers, params=params)
            # Don't leak credentials across hosts on redirect.
            resp = await client.send(req, stream=True)
            try:
                if resp.is_redirect and (loc := resp.headers.get("location")):
                    new_url = str(httpx.URL(url).join(loc))
                    if httpx.URL(new_url).host != httpx.URL(url).host:
                        headers = {
                            k: v for k, v in (headers or {}).items() if k.lower() not in ("authorization", "cookie")
                        }
                    url, params = new_url, None
                    continue
                body = bytearray()
                async for chunk in resp.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise SsrfError("response too large")
                resp._content = bytes(body)  # noqa: SLF001
                return resp
            finally:
                await resp.aclose()
        raise SsrfError("too many redirects")
