"""HTTP for pull connectors: every request goes through the SSRF guard; adds TLS options, retry/backoff and clean errors.

TLS: verification is ON by default. A source may pin its own CA (`ca_pem`) for an internal PKI, or — as an explicit, visible
opt-out for self-signed internal appliances — set `verify_tls=false`. Credentials are never included in raised errors."""

import asyncio
import ssl
from typing import Any

import httpx

from app.core import ssrf

# Test seams (mirrors generic_rest): a MockTransport / fake resolver injected by tests.
HTTP_TRANSPORT: httpx.AsyncBaseTransport | None = None
RESOLVER: ssrf.Resolver = ssrf.default_resolver

RETRY_STATUS = {429, 500, 502, 503, 504}


class SourceError(Exception):
    """A pull from the upstream failed. The message is safe to store and show (no secrets)."""


def tls_transport(verify_tls: bool, ca_pem: str | None) -> httpx.AsyncBaseTransport | None:
    if HTTP_TRANSPORT is not None:
        return HTTP_TRANSPORT
    if verify_tls and not ca_pem:
        return None  # default transport, system trust store
    if not verify_tls:
        return httpx.AsyncHTTPTransport(retries=0, verify=False)  # noqa: S501  (explicit per-source opt-out)
    try:
        ctx = ssl.create_default_context(cadata=ca_pem)
    except (ssl.SSLError, ValueError):
        raise SourceError("ca_pem is not a valid PEM certificate bundle") from None
    return httpx.AsyncHTTPTransport(retries=0, verify=ctx)


async def request_raw(
    method: str,
    url: str,
    *,
    headers: dict[str, str],
    params: dict[str, Any] | None = None,
    json_body: Any = None,
    verify_tls: bool = True,
    ca_pem: str | None = None,
    tls_server_name: str | None = None,
    timeout_s: float = 60.0,
    attempts: int = 4,
    max_bytes: int | None = None,
) -> httpx.Response:
    """SSRF-guarded request with retry/backoff on 429/5xx. Returns a successful response or raises SourceError."""
    transport = tls_transport(verify_tls, ca_pem)
    last = "no response"
    for attempt in range(attempts):
        try:
            resp = await ssrf.fetch(
                method,
                url,
                headers=headers,
                params=params,
                json_body=json_body,
                timeout_s=timeout_s,
                transport=transport,
                resolver=RESOLVER,
                sni_hostname=tls_server_name,
                max_bytes=max_bytes,
            )
        except ssrf.SsrfError as exc:
            raise SourceError(f"blocked by outbound policy: {exc}") from None
        except httpx.HTTPError as exc:
            last = type(exc).__name__
        else:
            if resp.status_code in (401, 403):
                raise SourceError(
                    f"authentication rejected (HTTP {resp.status_code}); check the credential and its role"
                )
            if resp.status_code in RETRY_STATUS:
                last = f"HTTP {resp.status_code}"
                retry_after = resp.headers.get("retry-after", "")
                await asyncio.sleep(min(int(retry_after), 60) if retry_after.isdigit() else min(2**attempt, 30))
                continue
            if resp.status_code >= 400:
                raise SourceError(f"HTTP {resp.status_code}: {_error_text(resp)}")
            return resp
        await asyncio.sleep(min(2**attempt, 30))
    raise SourceError(f"upstream unavailable ({last})")


async def request_json(method: str, url: str, **kwargs: Any) -> Any:
    resp = await request_raw(method, url, **kwargs)
    try:
        return resp.json()
    except ValueError:
        raise SourceError("response is not valid JSON") from None


async def request_text(method: str, url: str, **kwargs: Any) -> str:
    return (await request_raw(method, url, **kwargs)).text


def _error_text(resp: httpx.Response) -> str:
    try:
        body = resp.json()
        err = body.get("error", body) if isinstance(body, dict) else body
        msg = err.get("message") or err.get("code") if isinstance(err, dict) else err
        return str(msg)[:200]
    except ValueError:
        return resp.text[:120]
