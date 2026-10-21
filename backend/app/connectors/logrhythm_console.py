# ruff: noqa: E501
"""LogRhythm Web Console search: the platform's way of asking LogRhythm (ADR 0025).

The Web Console (default port 8443) is a Node service whose browser UI talks to the SIEM over one socket.io connection. This module speaks
that protocol, so a search is exactly what an analyst's own Search tool does, and it returns what the `:8501` Search API never does: the raw
log text (`logMessage`) next to the parsed metadata. Verified on a production LogRhythm 7.x on 2026-10-21:

* Login: `GET /api/webconsole/config.js` hands out the `_csrf` + `XSRF-TOKEN` cookies; `POST /api/webconsole/login` with JSON
  `{username, password, _csrf}` and the header `XSRF-TOKEN` answers 200 and a `connect.sid` session cookie (401 = refused, with a JSON message).
* Socket: `wss://host:8443/api/webconsole/socket.io/?EIO=4&transport=websocket`. Engine.IO v4: the server sends `0{...}`, we answer `40`, it
  answers `40{...}`; `2` is a ping we answer with `3`; `42["message", "<json envelope>"]` carries everything else. An envelope is
  `{source, destination, messageType, ver, data, method, _tracker}` and the reply echoes `_tracker`.
* A search is a TASK: `TaskService/CreateSearchRequest` (a `searchConfiguration` shaped like the Search tool's), polled with
  `TaskService/GetTaskRequest` (`shortResults`: Searching, First Results, Completed: ..., Search Failed; `numResults` grows by 5,000), read with
  `LogsService/LogsRequest` (pages of items: metadata + `logMessage`), removed with `TaskService/RemoveTasksRequest`.
* The server-side filter is only honoured when the filter group carries `filterType: 1000`; `searchMode: 3` keeps the newest results when a
  search is capped (without it a task stops at 10,000).

This is the console's own protocol, not a documented API: it is isolated here, every failure is a clean `ConsoleError`, and nothing in this
file logs or echoes a credential. The outbound SSRF policy applies to the login AND to the socket (the validated IP is pinned)."""

import asyncio
import contextlib
import copy
import hashlib
import json
import ssl
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
import websockets
from websockets.exceptions import WebSocketException

from app.connectors import _http
from app.connectors._http import SourceError
from app.core import ssrf

# Test seam: replaces the real WebSocket connect. Called as WS_CONNECT(url, headers=, host=, port=, server_hostname=, ssl_ctx=).
WS_CONNECT: Callable[..., Awaitable[Any]] | None = None

SOCKET_PATH = "/api/webconsole/socket.io/"
PAGE_SIZE = 200
GROUP_FILTER_TYPE = 1000  # the filter group must carry this or the console silently ignores the filter
SEARCH_MODE_NEWEST_FIRST = 3
LOGIN_BACKOFF_S = 300  # after a refused login nothing retries for this long: a wrong password must not lock the account


class ConsoleError(SourceError):
    """The console could not answer. The message is safe to store and show (no credentials)."""


class BudgetExceeded(ConsoleError):
    """The caller's time budget ran out. Not a failure of the console: the caller keeps what it already has and reports a partial search."""


class _ConnectionLost(ConsoleError):
    pass


class _SessionRejected(ConsoleError):
    pass


@dataclass(frozen=True)
class ConsoleSettings:
    url: str
    username: str
    password: str = field(repr=False)
    verify_tls: bool = True
    ca_pem: str | None = None
    tls_server_name: str | None = None
    query_timeout_min: int = 5
    max_results: int = 30_000
    parallel: int = 2
    poll_s: float = 1.0
    task_timeout_s: float = 240.0
    timeout_s: float = 60.0


@dataclass
class SearchOutcome:
    logs: list[dict[str, Any]]
    status: str  # the task's own words: "Completed: All Results", "Completed: Max Results", "First Results" (stopped early), "Search Failed" ...
    total: int  # results the task had collected when it was read
    capped: bool  # more results exist than `logs`


async def _sleep(s: float) -> None:
    await asyncio.sleep(s)


# ---- Engine.IO / Socket.IO v4 over a websocket ---------------------------------------------------------------------------------
class _Socket:
    def __init__(self, ws: Any) -> None:
        self._ws = ws
        self._waiters: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._reader: asyncio.Task[None] | None = None
        self.closed = False

    async def open(self, wait_s: float) -> None:
        try:
            first = await asyncio.wait_for(self._ws.recv(), wait_s)
            if not (isinstance(first, str) and first.startswith("0")):
                raise ConsoleError("the console socket did not answer like Engine.IO v4")
            await self._ws.send("40")
            while True:
                frame = await asyncio.wait_for(self._ws.recv(), wait_s)
                if not isinstance(frame, str):
                    continue
                if frame.startswith("40"):
                    break
                if frame.startswith("44"):
                    raise _SessionRejected("the console refused the socket (session not accepted)")
                if frame == "2":
                    await self._ws.send("3")
        except TimeoutError:
            raise ConsoleError("the console socket did not finish its handshake in time") from None
        except (OSError, WebSocketException) as exc:
            raise ConsoleError(f"the console socket closed during the handshake ({type(exc).__name__})") from None
        self._reader = asyncio.create_task(self._read())

    async def _read(self) -> None:
        try:
            while True:
                frame = await self._ws.recv()
                if not isinstance(frame, str):
                    continue
                if frame == "2":
                    await self._ws.send("3")
                elif frame.startswith("42"):
                    self._event(frame[2:])
                elif frame.startswith(("41", "1")):
                    break
        except Exception:  # noqa: S110  (any failure of the pipe ends the reader; the waiters are failed below)
            pass
        finally:
            self.closed = True
            for waiter in list(self._waiters.values()):
                if not waiter.done():
                    waiter.set_exception(_ConnectionLost("the console connection was lost"))

    def _event(self, payload: str) -> None:
        i = 0
        while i < len(payload) and payload[i].isdigit():  # an ack id, which this client never asks for
            i += 1
        try:
            name, data = json.loads(payload[i:])[:2]
            msg = json.loads(data) if isinstance(data, str) else data
        except (ValueError, TypeError):
            return
        if name != "message" or not isinstance(msg, dict):
            return
        waiter = self._waiters.get(str(msg.get("_tracker")))
        if waiter is not None and not waiter.done():
            waiter.set_result(msg)

    async def _send(self, dest: str, mtype: str, data: dict[str, Any], method: str, tracker: str) -> None:
        envelope = {
            "source": None,
            "destination": dest,
            "messageType": mtype,
            "ver": 1,
            "data": data,
            "method": method,
            "_tracker": tracker,
        }
        try:
            await self._ws.send("42" + json.dumps(["message", json.dumps(envelope, separators=(",", ":"))]))
        except (OSError, WebSocketException):
            self.closed = True
            raise _ConnectionLost("the console connection was lost") from None

    async def call(
        self, dest: str, mtype: str, data: dict[str, Any], method: str = "post", wait_s: float = 60.0
    ) -> dict[str, Any]:
        if self.closed:
            raise _ConnectionLost("the console connection was lost")
        tracker = str(uuid.uuid4())
        waiter: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._waiters[tracker] = waiter
        try:
            await self._send(dest, mtype, data, method, tracker)
            msg = await asyncio.wait_for(waiter, wait_s)
        except TimeoutError:
            raise ConsoleError(f"the console did not answer {mtype} in {wait_s:.0f}s") from None
        finally:
            self._waiters.pop(tracker, None)
        if msg.get("error") or msg.get("messageType") == "error":
            raise ConsoleError(f"the console refused {mtype}: {str(msg.get('error') or msg.get('data') or '')[:160]}")
        return msg

    async def notify(self, dest: str, mtype: str, data: dict[str, Any], method: str) -> None:
        """Fire and forget (the console does not answer a removal)."""
        if not self.closed:
            await self._send(dest, mtype, data, method, str(uuid.uuid4()))

    async def close(self) -> None:
        self.closed = True
        with contextlib.suppress(Exception):
            await self._ws.close()
        if self._reader is not None:
            self._reader.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reader


# ---- the filter and task configuration -----------------------------------------------------------------------------------------
def console_filter(query_filter: dict[str, Any]) -> dict[str, Any]:
    """A `queryFilter` as the Search API takes it, made acceptable to the console: its top filter group must carry filterType 1000."""
    qf = copy.deepcopy(query_filter)
    qf.pop("isSavedFilter", None)
    group = qf.get("filterGroup")
    if isinstance(group, dict):
        group["filterType"] = GROUP_FILTER_TYPE
    return qf


def task_config(s: ConsoleSettings, query_filter: dict[str, Any], start: datetime, end: datetime) -> dict[str, Any]:
    def iso(d: datetime) -> str:
        return d.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "name": "Ad Hoc Search",
        "description": "Threat Hunt platform search",
        "maxMsgsToQuery": s.max_results,
        "logCacheSize": 10000,
        "aggregateLogCacheSize": 10000,
        "queryTimeout": s.query_timeout_min,
        "queryRawLog": True,
        "queryEventManager": False,
        "useDefaultLogRepositories": True,
        "searchType": 1,
        "logRepositoryIds": [],
        "enableIntelligentIndexing": False,
        "searchId": 0,
        "webLayoutId": 0,
        "dateUsed": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "searchMode": SEARCH_MODE_NEWEST_FIRST,
        "queryLogSources": [],
        "queryLogSourceLists": [],
        "queryFilter": console_filter(query_filter),
        "dateCriteria": {"useInsertedDate": False, "dateMin": iso(start), "dateMax": iso(end)},
    }


# ---- the client -------------------------------------------------------------------------------------------------------------------
class ConsoleClient:
    """One logged-in session and one socket per (console, account), shared by every search of that source. Searches run at most
    `parallel` at a time (the console serves a handful of simultaneous Hot searches)."""

    def __init__(self, settings: ConsoleSettings) -> None:
        self.s = settings
        self._sem = asyncio.Semaphore(max(1, settings.parallel))
        self._lock = asyncio.Lock()
        self._sock: _Socket | None = None
        self._blocked_until = 0.0
        self._blocked_msg = ""

    # -- HTTP login -----------------------------------------------------------------------------------------------------------
    async def _http(self, method: str, path: str, *, headers: dict[str, str], json_body: Any = None) -> httpx.Response:
        try:
            return await ssrf.fetch(
                method,
                self.s.url.rstrip("/") + path,
                headers=headers,
                json_body=json_body,
                timeout_s=self.s.timeout_s,
                transport=_http.tls_transport(self.s.verify_tls, self.s.ca_pem),
                resolver=_http.RESOLVER,
                sni_hostname=self.s.tls_server_name,
                max_bytes=1_000_000,
            )
        except ssrf.SsrfError as exc:
            raise ConsoleError(f"blocked by outbound policy: {exc}") from None
        except httpx.HTTPError as exc:
            raise ConsoleError(f"the console is unreachable ({type(exc).__name__})") from None

    @staticmethod
    def _cookies(resp: httpx.Response, jar: dict[str, str]) -> None:
        for raw in resp.headers.get_list("set-cookie"):
            name, _, rest = raw.partition("=")
            if name.strip():
                jar[name.strip()] = rest.split(";", 1)[0]

    async def _login(self) -> str:
        now = time.monotonic()
        if self._blocked_until > now:
            raise ConsoleError(self._blocked_msg)
        base = self.s.url.rstrip("/")
        jar: dict[str, str] = {}

        def cookie() -> str:
            return "; ".join(f"{k}={v}" for k, v in jar.items())

        resp = await self._http("GET", "/api/webconsole/config.js", headers={"Accept": "*/*"})
        self._cookies(resp, jar)
        xsrf = jar.get("XSRF-TOKEN")
        if resp.status_code != 200 or not xsrf:
            raise ConsoleError(
                f"the console did not issue a CSRF token (HTTP {resp.status_code}); is this the Web Console address?"
            )
        resp = await self._http(
            "POST",
            "/api/webconsole/login",
            headers={
                "XSRF-TOKEN": xsrf,
                "Cookie": cookie(),
                "Referer": base + "/login",
                "Origin": base,
                "Accept": "application/json",
            },
            json_body={"username": self.s.username, "password": self.s.password, "_csrf": xsrf},
        )
        if resp.status_code in (401, 403):
            msg, mfa = "", False
            with contextlib.suppress(ValueError):
                body = resp.json()
                if isinstance(body, dict):
                    mfa = bool(body.get("multiFactorAuthRequired"))
                    msg = str(body.get("message") or "")[:120]
            if mfa:
                text = "the console account needs multi-factor authentication; use a dedicated read-only account without it"
            else:
                text = "the console refused the username/password" + (f" ({msg})" if msg else "")
            self._blocked_until = time.monotonic() + LOGIN_BACKOFF_S
            self._blocked_msg = f"{text}; not retrying for {LOGIN_BACKOFF_S // 60} minutes so the account is not locked"
            raise ConsoleError(text)
        if resp.status_code != 200:
            raise ConsoleError(f"the console login failed (HTTP {resp.status_code})")
        self._cookies(resp, jar)
        if "connect.sid" not in jar:
            raise ConsoleError("the console accepted the login but sent no session")
        return cookie()

    # -- socket -----------------------------------------------------------------------------------------------------------------
    def _ssl_context(self) -> ssl.SSLContext:
        if not self.s.verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # noqa: S502  (explicit per-source opt-out, as for the HTTP transport)
            return ctx
        try:
            return ssl.create_default_context(cadata=self.s.ca_pem) if self.s.ca_pem else ssl.create_default_context()
        except (ssl.SSLError, ValueError):
            raise ConsoleError("ca_pem is not a valid PEM certificate bundle") from None

    async def _open_socket(self, cookie: str) -> _Socket:
        probe = self.s.url.rstrip("/") + "/"
        try:
            host, port, addrs = await ssrf.validate_url(probe, _http.RESOLVER)
        except ssrf.SsrfError as exc:
            raise ConsoleError(f"blocked by outbound policy: {exc}") from None
        origin = self.s.url.rstrip("/")
        netloc = urlsplit(origin).netloc
        url = f"wss://{netloc}{SOCKET_PATH}?EIO=4&transport=websocket"
        headers = {"Cookie": cookie, "Origin": origin}
        sni = self.s.tls_server_name or host
        try:
            if WS_CONNECT is not None:
                ws = await WS_CONNECT(url, headers=headers, host=addrs[0], port=port, server_hostname=sni, ssl_ctx=None)
            else:
                ws = await websockets.connect(
                    url,
                    additional_headers=headers,
                    ssl=self._ssl_context(),
                    server_hostname=sni,
                    host=addrs[0],  # the address the outbound policy validated: no second DNS lookup
                    port=port,
                    proxy=None,
                    ping_interval=None,  # Engine.IO has its own ping
                    max_size=64 * 1024 * 1024,
                    open_timeout=self.s.timeout_s,
                )
        except (OSError, TimeoutError, WebSocketException) as exc:
            raise ConsoleError(f"cannot open the console socket ({type(exc).__name__}): {str(exc)[:120]}") from None
        sock = _Socket(ws)
        try:
            await sock.open(self.s.timeout_s)
        except BaseException:
            await sock.close()
            raise
        return sock

    async def _ensure(self) -> _Socket:
        async with self._lock:
            if self._sock is not None and not self._sock.closed:
                return self._sock
            for _ in range(2):
                cookie = await self._login()
                try:
                    self._sock = await self._open_socket(cookie)
                    return self._sock
                except _SessionRejected:
                    continue
            raise ConsoleError("the console rejected the session twice")

    async def _drop(self, sock: _Socket | None) -> None:
        async with self._lock:
            if sock is not None and sock is self._sock:
                self._sock = None
        if sock is not None:
            await sock.close()

    async def ping(self) -> str:
        """Login + socket handshake: proves the address, the certificate, the credentials and the socket service."""
        await self._ensure()
        return "console reachable, login accepted, socket open"

    async def close(self) -> None:
        await self._drop(self._sock)

    # -- searching --------------------------------------------------------------------------------------------------------------
    async def run_search(
        self,
        query_filter: dict[str, Any],
        start: datetime,
        end: datetime,
        *,
        max_logs: int | None = None,
        deadline: float | None = None,
    ) -> SearchOutcome:
        """One search over [start, end]: the logs matching `query_filter` (at most `max_logs` when given, newest first; otherwise everything the
        task collected, up to `max_results`). The task is always removed afterwards. `deadline` (a time.monotonic() value) bounds the whole
        search: past it the search is given up with BudgetExceeded, mid-wait or between pages, so one big search cannot outlive its caller's budget."""
        last: ConsoleError | None = None
        for _ in range(2):  # one retry on a connection that died under us
            sock: _Socket | None = None
            try:
                async with self._sem:
                    sock = await self._ensure()
                    return await self._run_once(sock, query_filter, start, end, max_logs, deadline)
            except _ConnectionLost as exc:
                last = exc
                await self._drop(sock)
        raise last or ConsoleError("the console connection was lost")

    async def _run_once(
        self,
        sock: _Socket,
        query_filter: dict[str, Any],
        start: datetime,
        end: datetime,
        max_logs: int | None,
        deadline: float | None,
    ) -> SearchOutcome:
        guid = str(uuid.uuid4())
        try:
            await sock.call(
                "TaskService",
                "CreateSearchRequest",
                {"action": 0, "searchGuid": guid, "searchConfiguration": task_config(self.s, query_filter, start, end)},
                wait_s=self.s.timeout_s,
            )
            status, total = await self._wait(sock, guid, max_logs, deadline)
            if status.startswith("Search "):  # Search Failed / Search Cancelled
                return SearchOutcome([], status, total, False)
            if max_logs is None and "Max Results" in status:
                # The caller wants EVERYTHING of this window and the task hit its cap, so it will split the window and search again:
                # reading 30,000 logs (about a minute) only to discard them is the single most expensive thing a hunt could do.
                return SearchOutcome([], status, total, True)
            want = total if max_logs is None else min(total, max_logs)
            logs = await self._page(sock, guid, want, deadline) if want else []
            # More exists than was read when the task held more, hit its own cap, or was still running when we stopped (the console delivers its
            # results in batches of 5,000, so stopping at exactly the limit says nothing about what is left).
            more = (
                total > len(logs)
                or "Max Results" in status
                or "Partial" in status
                or not status.startswith("Completed")
            )
            return SearchOutcome(logs, status, total, more)
        finally:
            with contextlib.suppress(Exception):
                await sock.notify("TaskService", "RemoveTasksRequest", {"taskIds": [guid]}, "delete")

    async def _wait(self, sock: _Socket, guid: str, max_logs: int | None, budget: float | None) -> tuple[str, int]:
        deadline = time.monotonic() + self.s.task_timeout_s
        while True:
            data = (await sock.call("TaskService", "GetTaskRequest", {"taskId": guid}, "get", self.s.timeout_s)).get(
                "data"
            ) or {}
            status = str(data.get("shortResults") or "")
            try:
                n = int(data.get("numResults") or 0)
            except (TypeError, ValueError):
                n = 0
            if status.startswith(("Completed", "Search ")):
                return status, n
            if max_logs is not None and n >= max_logs:
                return status, n  # enough to answer: no need to wait for the rest
            if budget is not None and time.monotonic() > budget:
                raise BudgetExceeded("the time budget ran out while a console search was running")
            if time.monotonic() > deadline:
                raise ConsoleError(f"the console search did not finish in {self.s.task_timeout_s:.0f}s")
            await _sleep(self.s.poll_s)

    async def _page(self, sock: _Socket, guid: str, want: int, budget: float | None) -> list[dict[str, Any]]:
        logs: list[dict[str, Any]] = []
        while len(logs) < want:
            if budget is not None and time.monotonic() > budget:
                raise BudgetExceeded("the time budget ran out while reading the logs of a console search")
            size = min(PAGE_SIZE, want - len(logs))
            msg = await sock.call(
                "LogsService",
                "LogsRequest",
                {
                    "searchGuid": guid,
                    "paginator": {"origin": len(logs), "page_size": size},
                    "search": {"query": "", "sort": [{"fieldName": "normalDate", "order": "dsc"}]},
                    "widgetType": 1,
                    "field": "",
                    "scrollIdMap": {},
                },
                "get",
                self.s.timeout_s,
            )
            items = [i for i in (msg.get("data") or {}).get("items") or [] if isinstance(i, dict)]
            if not items:
                break
            logs += items
        return logs[:want]


# ---- one client per console account, per event loop ---------------------------------------------------------------------------------
_CLIENTS: dict[tuple[Any, ...], ConsoleClient] = {}


def client_for(settings: ConsoleSettings) -> ConsoleClient:
    key = (
        id(asyncio.get_running_loop()),
        settings.url,
        settings.username,
        hashlib.sha256(settings.password.encode()).hexdigest()[:16],
        settings.verify_tls,
        hashlib.sha256((settings.ca_pem or "").encode()).hexdigest()[:16],
        settings.tls_server_name,
        settings.parallel,
        settings.query_timeout_min,
        settings.max_results,
    )
    client = _CLIENTS.get(key)
    if client is None:
        if len(_CLIENTS) > 64:  # rotated credentials / dead loops must not accumulate
            _CLIENTS.clear()
        client = _CLIENTS[key] = ConsoleClient(settings)
    return client
