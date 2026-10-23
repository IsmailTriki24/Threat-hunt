"""HTTP for pull connectors: every request goes through the SSRF guard; adds TLS options, retry/backoff and clean errors.

TLS: verification is ON by default. A source may pin its own CA (`ca_pem`) for an internal PKI, or — as an explicit, visible
opt-out for self-signed internal appliances — set `verify_tls=false`. Credentials are never included in raised errors."""

import asyncio
import hashlib
import ssl
import time
from contextvars import ContextVar
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.core import ssrf

# Test seams (mirrors generic_rest): a MockTransport / fake resolver injected by tests.
HTTP_TRANSPORT: httpx.AsyncBaseTransport | None = None
RESOLVER: ssrf.Resolver = ssrf.default_resolver

RETRY_STATUS = {429, 500, 502, 503, 504}


class SourceError(Exception):
    """A pull from the upstream failed. The message is safe to store and show (no secrets)."""


class RateLimited(SourceError):
    """The upstream answered 429 and asked us to stay away for `retry_in_s`. Raised at once instead of sleeping through a
    long `Retry-After`, so a search returns what the other sources found and a collection run ends and resumes later."""

    def __init__(self, retry_in_s: float) -> None:
        self.retry_in_s = retry_in_s
        super().__init__(
            f"the source is rate-limiting requests (HTTP 429); try again in about {max(1, round(retry_in_s))} s"
        )


# How long one call may sleep to ride out a 429 before giving up with RateLimited. Short by default (a person is waiting on
# the search); background jobs that can afford to wait raise it with `patience()`.
THROTTLE_PATIENCE_S: ContextVar[float] = ContextVar("throttle_patience_s", default=5.0)
MAX_COOLDOWN_S = 120.0

# Per credential and endpoint: the instant (time.monotonic) until which the upstream asked us to stay away. Shared by every
# job in this process, so one 429 stops the collectors, sweeps and searches together instead of each retrying on its own.
_cooldowns: dict[str, float] = {}


class patience:  # noqa: N801  (used as a context manager, like contextlib helpers)
    """`with patience(90):` lets the calls inside wait up to 90 s for an upstream's rate limit to clear."""

    def __init__(self, seconds: float) -> None:
        self._seconds = seconds
        self._token: Any = None

    def __enter__(self) -> None:
        self._token = THROTTLE_PATIENCE_S.set(self._seconds)

    def __exit__(self, *_: object) -> None:
        THROTTLE_PATIENCE_S.reset(self._token)


def reset_cooldowns() -> None:
    _cooldowns.clear()


def _throttle_key(url: str, headers: dict[str, str]) -> str:
    """Quotas are per API key and per endpoint. The key is hashed: it never appears in memory dumps, logs or errors."""
    auth = next((v for k, v in headers.items() if k.lower() == "authorization"), "")
    parts = urlsplit(url)
    return f"{hashlib.sha256(auth.encode()).hexdigest()[:16]}|{parts.netloc}{parts.path}"


async def _respect_cooldown(key: str) -> None:
    remaining = _cooldowns.get(key, 0.0) - time.monotonic()
    if remaining <= 0:
        return
    if remaining > THROTTLE_PATIENCE_S.get():
        raise RateLimited(remaining)
    await asyncio.sleep(remaining)


def _start_cooldown(key: str, seconds: float) -> None:
    now = time.monotonic()
    for k in [k for k, until in _cooldowns.items() if until <= now]:
        del _cooldowns[k]
    _cooldowns[key] = max(_cooldowns.get(key, 0.0), now + seconds)


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
    key = _throttle_key(url, headers)
    last = "no response"
    throttled_for = 0.0
    for attempt in range(attempts):
        await _respect_cooldown(key)
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
            if resp.status_code == 429:
                retry_after = resp.headers.get("retry-after", "")
                throttled_for = min(float(retry_after) if retry_after.isdigit() else float(2**attempt), MAX_COOLDOWN_S)
                _start_cooldown(key, throttled_for)
                last = "HTTP 429"
                continue  # the cooldown is honoured (slept through or raised as RateLimited) at the top of the loop
            if resp.status_code in RETRY_STATUS:
                last = f"HTTP {resp.status_code}"
                retry_after = resp.headers.get("retry-after", "")
                await asyncio.sleep(min(int(retry_after), 60) if retry_after.isdigit() else min(2**attempt, 30))
                continue
            if resp.status_code >= 400:
                raise SourceError(f"HTTP {resp.status_code}: {_error_text(resp)}")
            return resp
        await asyncio.sleep(min(2**attempt, 30))
    if last == "HTTP 429":
        raise RateLimited(throttled_for)
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
