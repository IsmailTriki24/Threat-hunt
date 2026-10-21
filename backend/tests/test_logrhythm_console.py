# ruff: noqa: E501
"""The LogRhythm Web Console client (ADR 0025): login, the Engine.IO socket, a search task from creation to removal, and everything that can
go wrong on the way. The console is imitated at the wire: HTTP login through a MockTransport, the socket through the module's WS_CONNECT seam;
one test runs a real TLS websocket server to prove certificate pinning and hostname verification on the socket itself."""

import asyncio
import json
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from app.connectors import _http, registry
from app.connectors import logrhythm_console as lc
from app.connectors.logrhythm import ioc_query_filter

PUBLIC = "93.184.216.34"
NOW = datetime.now(UTC).replace(microsecond=0)
START, END = NOW - timedelta(minutes=10), NOW
PASSWORD = "s3cr3t-PW-XYZ"


async def _resolve(host, port):
    return [PUBLIC]


def log(i: int, **over: Any) -> dict[str, Any]:
    ms = int(NOW.timestamp() * 1000) + i
    return {
        "messageId": str(i),
        "logDate": ms,
        "normalDate": ms,
        "classificationName": "Authentication Failure",
        "originIp": "10.0.0.1",
        "logMessage": f"<Event><EventID>4625</EventID><Data>raw {i}</Data></Event>",
        **over,
    }


class _Ws:
    """The browser-facing side of the console socket: speaks Engine.IO v4 frames."""

    def __init__(self, srv: "Console") -> None:
        self.srv = srv
        self.q: asyncio.Queue[str | None] = asyncio.Queue()
        self.q.put_nowait('0{"sid":"abc","upgrades":[],"pingInterval":25000,"pingTimeout":20000}')
        self.sent: list[str] = []
        self.closed = False

    async def recv(self) -> str:
        item = await self.q.get()
        if item is None:
            raise OSError("closed")
        return item

    async def send(self, frame: str) -> None:
        if self.closed:
            raise OSError("closed")
        self.sent.append(frame)
        if frame == "40":
            if self.srv.reject_handshakes > 0:
                self.srv.reject_handshakes -= 1
                self.q.put_nowait('44{"message":"Not authorized"}')
            else:
                self.q.put_nowait('40{"sid":"s1"}')
        elif frame.startswith("42"):
            self.srv.on_message(self, frame)

    async def close(self) -> None:
        self.closed = True
        self.q.put_nowait(None)

    def reply(self, env: dict[str, Any], data: Any, **extra: Any) -> None:
        msg = {
            "source": None,
            "destination": env["destination"],
            "messageType": env["messageType"].replace("Request", "Response"),
            "ver": 1,
            "data": data,
            "method": env["method"],
            "_tracker": env["_tracker"],
            **extra,
        }
        self.q.put_nowait("42" + json.dumps(["message", json.dumps(msg)]))


class Console:
    """A scripted console. `results(n, config)` gives (final status, items) for the n-th search."""

    def __init__(
        self, results: Callable[[int, dict[str, Any]], tuple[str, list[dict[str, Any]]]] | None = None
    ) -> None:
        self.results = results or (lambda n, cfg: ("Completed: All Results", [log(i) for i in range(3)]))
        self.login_status = 200
        self.login_body: dict[str, Any] = {"message": "Invalid credentials"}
        self.no_csrf = False
        self.reject_handshakes = 0
        self.drop_on_create = 0
        self.errors: dict[str, str] = {}
        self.stuck = False
        self.logins: list[httpx.Request] = []
        self.sockets: list[_Ws] = []
        self.ws_calls: list[dict[str, Any]] = []
        self.envelopes: list[dict[str, Any]] = []
        self.removed: list[str] = []
        self.tasks: dict[str, dict[str, Any]] = {}
        self.searches = 0

    # HTTP -----------------------------------------------------------------------------------------------------------------
    def http(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/webconsole/config.js":
            cookies = (
                []
                if self.no_csrf
                else [("set-cookie", "_csrf=c1; Path=/"), ("set-cookie", "XSRF-TOKEN=x1; Path=/; HttpOnly")]
            )
            return httpx.Response(200, headers=cookies, text="(function(){})()")
        if request.url.path == "/api/webconsole/login":
            self.logins.append(request)
            if self.login_status != 200:
                return httpx.Response(self.login_status, json=self.login_body)
            return httpx.Response(
                200,
                headers=[
                    ("set-cookie", "XSRF-TOKEN=x2; Path=/"),
                    ("set-cookie", "connect.sid=s%3Aabc.sig; Path=/; HttpOnly"),
                ],
            )
        return httpx.Response(404)

    # socket ---------------------------------------------------------------------------------------------------------------
    async def connect(
        self, url: str, *, headers: dict[str, str], host: str, port: int, server_hostname: str, ssl_ctx: Any
    ) -> _Ws:
        self.ws_calls.append(
            {"url": url, "headers": headers, "host": host, "port": port, "server_hostname": server_hostname}
        )
        ws = _Ws(self)
        self.sockets.append(ws)
        return ws

    def on_message(self, ws: _Ws, frame: str) -> None:
        name, payload = json.loads(frame[2:])[:2]
        assert name == "message"
        env = json.loads(payload)
        self.envelopes.append(env)
        mtype, data = env["messageType"], env["data"]
        if mtype in self.errors:
            return ws.reply(env, None, error=self.errors[mtype])
        if mtype == "CreateSearchRequest":
            if self.drop_on_create > 0:
                self.drop_on_create -= 1
                ws.q.put_nowait(None)
                return None
            self.searches += 1
            final, items = self.results(self.searches, data["searchConfiguration"])
            polls = (
                [("Searching", 0)]
                + ([("First Results", min(5000, len(items)))] if len(items) > 100 else [])
                + [(final, len(items))]
            )
            self.tasks[data["searchGuid"]] = {"items": items, "polls": polls, "config": data["searchConfiguration"]}
            return ws.reply(env, None)
        task = self.tasks.get(data.get("searchGuid") or data.get("taskId") or "")
        if mtype == "GetTaskRequest":
            assert task is not None
            polls = [("Searching", 0)] if self.stuck else task["polls"]
            short, n = polls[0] if len(polls) == 1 or self.stuck else polls.pop(0)
            return ws.reply(env, {"taskId": data["taskId"], "shortResults": short, "numResults": n})
        if mtype == "LogsRequest":
            assert task is not None
            origin, size = data["paginator"]["origin"], data["paginator"]["page_size"]
            items = task["items"]
            return ws.reply(
                env,
                {"allLogsCount": len(items), "filteredLogsCount": len(items), "items": items[origin : origin + size]},
            )
        if mtype == "RemoveTasksRequest":
            self.removed += data["taskIds"]
            return None
        raise AssertionError(f"unexpected message {mtype}")


@pytest.fixture
def console(monkeypatch):
    from app.core.config import Settings

    srv = Console()
    monkeypatch.setattr(_http, "HTTP_TRANSPORT", httpx.MockTransport(srv.http))
    monkeypatch.setattr(_http, "RESOLVER", _resolve)
    monkeypatch.setattr(
        "app.core.ssrf.get_settings", lambda: Settings(jwt_secret="x" * 40, outbound_allowed_ports="80,443,8443")
    )
    monkeypatch.setattr(lc, "WS_CONNECT", srv.connect)

    async def nosleep(_):
        await asyncio.sleep(0)

    monkeypatch.setattr(lc, "_sleep", nosleep)
    lc._CLIENTS.clear()
    yield srv
    lc._CLIENTS.clear()


def settings(**kw: Any) -> lc.ConsoleSettings:
    base = {"url": "https://lr.example:8443", "username": "svc", "password": PASSWORD, "poll_s": 0.0}
    return lc.ConsoleSettings(**{**base, **kw})


def client(**kw: Any) -> lc.ConsoleClient:
    return lc.ConsoleClient(settings(**kw))


# ---- the happy path ----------------------------------------------------------------------------------------------------------------
async def test_a_search_logs_in_opens_the_socket_reads_the_logs_with_their_raw_text_and_removes_the_task(console):
    c = client()
    out = await c.run_search(ioc_query_filter("ip", ["10.0.0.1"]), START, END)
    assert out.status == "Completed: All Results" and out.total == 3 and not out.capped
    assert [x["messageId"] for x in out.logs] == ["0", "1", "2"]
    assert all(
        "<EventID>4625</EventID>" in x["logMessage"] for x in out.logs
    )  # the raw text, which the Search API never returned

    login = console.logins[0]  # the CSRF handshake the browser does
    assert json.loads(login.content) == {"username": "svc", "password": PASSWORD, "_csrf": "x1"}
    assert login.headers["xsrf-token"] == "x1" and "_csrf=c1" in login.headers["cookie"]

    call = console.ws_calls[0]  # the socket: right URL, the session cookie, pinned address, certificate name
    assert call["url"] == "wss://lr.example:8443/api/webconsole/socket.io/?EIO=4&transport=websocket"
    assert (
        "connect.sid=s%3Aabc.sig" in call["headers"]["Cookie"]
        and call["headers"]["Origin"] == "https://lr.example:8443"
    )
    assert call["host"] == PUBLIC and call["port"] == 8443 and call["server_hostname"] == "lr.example"
    assert (
        console.sockets[0].sent[0] == "40"
    )  # Engine.IO v4: we connect the default namespace after the server's open packet

    create = next(e for e in console.envelopes if e["messageType"] == "CreateSearchRequest")
    assert (
        create["destination"] == "TaskService"
        and create["method"] == "post"
        and create["ver"] == 1
        and create["_tracker"]
    )
    cfg = create["data"]["searchConfiguration"]
    assert (
        cfg["searchMode"] == 3 and cfg["searchType"] == 1 and cfg["queryRawLog"] is True
    )  # newest first, the Search tool's own settings
    assert cfg["maxMsgsToQuery"] == 30_000 and cfg["queryTimeout"] == 5
    assert cfg["dateCriteria"] == {
        "useInsertedDate": False,
        "dateMin": START.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dateMax": END.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    assert cfg["queryFilter"]["filterGroup"]["filterType"] == 1000 and "isSavedFilter" not in cfg["queryFilter"]
    assert console.removed == [create["data"]["searchGuid"]]  # no task is left behind in the analyst's task list


def test_the_filter_is_made_acceptable_to_the_console_without_touching_the_original():
    original = ioc_query_filter("ip", ["10.0.0.1", "10.0.0.2"])
    converted = lc.console_filter(original)
    assert converted["filterGroup"]["filterType"] == 1000 and "isSavedFilter" not in converted
    assert "filterType" not in original["filterGroup"] and original["isSavedFilter"] is False
    assert (
        converted["filterGroup"]["filterItems"] == original["filterGroup"]["filterItems"]
    )  # the verified items are sent as they are


async def test_a_search_with_a_log_limit_stops_as_soon_as_enough_results_exist(console):
    console.results = lambda n, cfg: ("Completed: Max Results", [log(i) for i in range(6000)])
    out = await client().run_search(ioc_query_filter("ip", ["10.0.0.1"]), START, END, max_logs=450)
    assert len(out.logs) == 450 and out.capped and out.status == "First Results"  # it did not wait for the 6,000
    pages = [e["data"]["paginator"] for e in console.envelopes if e["messageType"] == "LogsRequest"]
    assert [p["origin"] for p in pages] == [0, 200, 400] and [p["page_size"] for p in pages] == [200, 200, 50]
    assert len(console.removed) == 1


async def test_a_search_for_everything_waits_for_the_task_and_pages_all_of_it(console):
    console.results = lambda n, cfg: ("Completed: All Results", [log(i) for i in range(450)])
    out = await client().run_search(ioc_query_filter("ip", ["10.0.0.1"]), START, END)
    assert (
        out.total == 450 and len(out.logs) == 450 and not out.capped and len({x["messageId"] for x in out.logs}) == 450
    )
    polls = [e for e in console.envelopes if e["messageType"] == "GetTaskRequest"]
    assert len(polls) >= 2  # Searching, then First Results, then Completed


async def test_an_empty_result_and_a_failed_search_are_reported_in_the_consoles_words(console):
    console.results = lambda n, cfg: ("Completed: No Results", [])
    out = await client().run_search(ioc_query_filter("ip", ["198.51.100.7"]), START, END)
    assert out.logs == [] and out.status == "Completed: No Results"
    console.results = lambda n, cfg: ("Search Failed", [])
    out = await client().run_search(ioc_query_filter("ip", ["198.51.100.7"]), START, END)
    assert out.logs == [] and out.status == "Search Failed"
    assert len(console.removed) == 2


async def test_the_socket_answers_the_servers_pings(console):
    c = client()
    await c.ping()
    ws = console.sockets[0]
    ws.q.put_nowait("2")
    for _ in range(50):
        if "3" in ws.sent:
            break
        await asyncio.sleep(0)
    assert "3" in ws.sent


async def test_ping_is_one_login_and_one_socket_and_searches_reuse_them(console):
    c = client()
    assert "login accepted" in await c.ping()
    await c.run_search(ioc_query_filter("ip", ["10.0.0.1"]), START, END)
    await c.run_search(ioc_query_filter("ip", ["10.0.0.2"]), START, END)
    assert len(console.logins) == 1 and len(console.ws_calls) == 1


async def test_searches_run_at_most_parallel_at_a_time(console):
    seen = {"now": 0, "max": 0}
    orig = lc.ConsoleClient._run_once

    async def counting(self, *a, **kw):
        seen["now"] += 1
        seen["max"] = max(seen["max"], seen["now"])
        try:
            await asyncio.sleep(0.01)
            return await orig(self, *a, **kw)
        finally:
            seen["now"] -= 1

    lc.ConsoleClient._run_once = counting  # type: ignore[method-assign]
    try:
        c = client(parallel=2)
        await asyncio.gather(*(c.run_search(ioc_query_filter("ip", [f"10.0.0.{i}"]), START, END) for i in range(6)))
    finally:
        lc.ConsoleClient._run_once = orig  # type: ignore[method-assign]
    assert seen["max"] == 2


# ---- login failures ----------------------------------------------------------------------------------------------------------------
async def test_a_refused_login_names_the_problem_never_leaks_the_password_and_is_not_retried(console):
    console.login_status = 401
    c = client()
    with pytest.raises(lc.ConsoleError) as exc:
        await c.ping()
    assert (
        "refused the username/password" in str(exc.value)
        and "Invalid credentials" in str(exc.value)
        and PASSWORD not in str(exc.value)
    )
    with pytest.raises(lc.ConsoleError) as again:  # a wrong password must not hammer the account into a lockout
        await c.ping()
    assert "not retrying" in str(again.value) and PASSWORD not in str(again.value)
    assert len(console.logins) == 1 and console.ws_calls == []


async def test_an_account_that_needs_multi_factor_authentication_is_refused_clearly(console):
    console.login_status = 401
    console.login_body = {"message": "Enter the code", "multiFactorAuthRequired": True}
    with pytest.raises(lc.ConsoleError, match="multi-factor"):
        await client().ping()


async def test_an_address_that_is_not_the_console_is_called_out(console):
    console.no_csrf = True
    with pytest.raises(lc.ConsoleError, match="CSRF token"):
        await client().ping()
    console.no_csrf = False
    console.login_status = 500
    with pytest.raises(lc.ConsoleError, match="HTTP 500"):
        await client().ping()


async def test_a_session_the_socket_refuses_is_logged_in_again_once(console):
    console.reject_handshakes = 1
    await client().ping()
    assert len(console.logins) == 2 and len(console.ws_calls) == 2
    console.reject_handshakes = 5
    with pytest.raises(lc.ConsoleError, match="rejected the session twice"):
        await client().ping()


# ---- the connection dying and the console complaining ---------------------------------------------------------------------------------
async def test_a_connection_that_dies_mid_search_is_reopened_and_the_search_repeated_once(console):
    console.drop_on_create = 1
    out = await client().run_search(ioc_query_filter("ip", ["10.0.0.1"]), START, END)
    assert len(out.logs) == 3 and len(console.ws_calls) == 2 and len(console.logins) == 2
    console.drop_on_create = 2
    with pytest.raises(lc.ConsoleError, match="lost"):
        await client().run_search(ioc_query_filter("ip", ["10.0.0.1"]), START, END)


async def test_an_error_from_the_console_is_a_clean_error_with_its_text(console):
    console.errors["CreateSearchRequest"] = "Query is too broad"
    with pytest.raises(lc.ConsoleError, match="CreateSearchRequest.*Query is too broad"):
        await client().run_search(ioc_query_filter("ip", ["10.0.0.1"]), START, END)


async def test_a_search_that_never_finishes_gives_up_and_still_removes_the_task(console):
    console.stuck = True
    with pytest.raises(lc.ConsoleError, match="did not finish"):
        await client(task_timeout_s=0.05).run_search(ioc_query_filter("ip", ["10.0.0.1"]), START, END)
    assert len(console.removed) == 1


# ---- outbound policy ---------------------------------------------------------------------------------------------------------------------
async def test_the_outbound_policy_applies_to_the_login_and_the_socket(console, monkeypatch):
    async def private(host, port):
        return ["10.1.2.3"]

    monkeypatch.setattr(_http, "RESOLVER", private)
    with pytest.raises(lc.ConsoleError, match="blocked by outbound policy"):
        await client().ping()
    assert console.logins == [] and console.ws_calls == []

    monkeypatch.setattr(_http, "RESOLVER", _resolve)
    with pytest.raises(lc.ConsoleError, match="port 9999 is not allowed"):
        await client(url="https://lr.example:9999").ping()


async def test_the_certificate_name_is_the_configured_one_when_the_console_is_reached_by_address(console):
    await client(tls_server_name="siem.corp.local").ping()
    assert console.ws_calls[0]["server_hostname"] == "siem.corp.local" and console.ws_calls[0]["host"] == PUBLIC


# ---- the connector on top ------------------------------------------------------------------------------------------------------------------
def lr(**cfg: Any):
    return registry.build(
        "logrhythm",
        {"console_url": "https://lr.example:8443", "hostname": "dc1", "console_poll_s": 0.2, **cfg},
        {"username": "svc", "password": PASSWORD},
    )


async def test_the_connector_searches_through_the_console_and_a_window_over_the_cap_is_split(console):
    def results(n, cfg):
        return ("Completed: Max Results", [log(0)]) if n == 1 else ("Completed: All Results", [log(n)])

    console.results = results
    out = await lr()._search_window(START, END)
    assert (
        len(console.envelopes) and console.searches == 3
    )  # the whole window hit the cap, so the two halves were searched
    assert {x["messageId"] for x in out} == {"2", "3"}
    reads = [e for e in console.envelopes if e["messageType"] == "LogsRequest"]
    assert len(reads) == 2  # the capped window's logs were never read: they would only have been thrown away
    first = next(e for e in console.envelopes if e["messageType"] == "CreateSearchRequest")["data"][
        "searchConfiguration"
    ]
    assert (
        first["queryFilter"]["filterGroup"]["filterItems"][0]["filterType"] == 23
    )  # the source's host filter is part of every search


async def test_a_capped_interactive_search_says_so(console):
    console.results = lambda n, cfg: ("Completed: Max Results", [log(i) for i in range(6000)])
    c = lr()
    c._filter_override = ioc_query_filter("ip", ["10.0.0.1"])
    out = await c._search_window(START, END, None, 300)
    assert len(out) == 300 and c.capped


async def test_the_connector_reports_a_console_that_is_not_configured_and_one_that_is_reachable(console):
    nothing = registry.build("logrhythm", {"hostname": "dc1"}, {"token": "legacy"})
    res = await nothing.test_connection()
    assert not res.ok and "console is not configured" in res.detail
    only_url = registry.build("logrhythm", {"console_url": "https://lr.example:8443"}, {"username": "svc"})
    assert "password" in (await only_url.test_connection()).detail
    ok = await lr().test_connection()
    assert ok.ok and "login accepted" in ok.detail
    health = await lr().health()
    assert health.status == "ok"
    console.login_status = 401
    lc._CLIENTS.clear()
    bad = await lr().test_connection()
    assert not bad.ok and PASSWORD not in bad.detail


def test_clients_are_shared_per_console_and_account_and_never_across_a_rotated_password():
    async def run():
        a = lc.client_for(settings())
        assert lc.client_for(settings()) is a
        assert lc.client_for(settings(password="rotated")) is not a
        assert lc.client_for(settings(url="https://other:8443")) is not a
        assert PASSWORD not in repr(settings())  # the password never shows in logs or tracebacks

    lc._CLIENTS.clear()
    asyncio.run(run())
    lc._CLIENTS.clear()


# ---- certificate pinning and hostname checks on the real socket -----------------------------------------------------------------------
@pytest.fixture
async def tls_console():
    import ssl
    import tempfile
    from pathlib import Path

    import websockets
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "siem.test.local")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("siem.test.local")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    d = Path(tempfile.mkdtemp())
    (d / "c.pem").write_text(pem)
    (d / "k.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        )
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "c.pem", d / "k.pem")

    async def handler(ws):
        await ws.send('0{"sid":"a","upgrades":[],"pingInterval":25000,"pingTimeout":20000}')
        async for frame in ws:
            if frame == "40":
                await ws.send('40{"sid":"s"}')

    server = await websockets.serve(handler, "127.0.0.1", 0, ssl=ctx)
    yield server.sockets[0].getsockname()[1], pem
    server.close()
    await server.wait_closed()


async def test_the_console_socket_verifies_a_pinned_certificate_and_its_hostname_for_real(tls_console, monkeypatch):
    from app.core.config import get_settings as real_settings

    port, pem = tls_console
    s = real_settings()
    monkeypatch.setattr(s, "outbound_allowed_networks", "127.0.0.1/32")
    monkeypatch.setattr(s, "outbound_allowed_ports", str(port))
    url = f"https://127.0.0.1:{port}"

    async def open_socket(**kw: Any) -> str:
        c = lc.ConsoleClient(settings(url=url, **kw))
        try:
            sock = await c._open_socket("connect.sid=x")
        except lc.ConsoleError as exc:
            return str(exc)
        await sock.close()
        return "ok"

    assert (
        await open_socket(ca_pem=pem, tls_server_name="siem.test.local") == "ok"
    )  # pinned certificate + matching name
    assert await open_socket(ca_pem=pem, tls_server_name="other.example") != "ok"  # right certificate, wrong hostname
    assert await open_socket(ca_pem=pem) != "ok"  # reached by IP, which the certificate does not name
    assert await open_socket() != "ok"  # self-signed and untrusted: the default is to refuse
    assert await open_socket(verify_tls=False) == "ok"  # explicit, visible opt-out
    assert "PEM" in await open_socket(ca_pem="not a certificate")


async def test_a_capped_search_for_everything_does_not_read_the_logs_it_is_about_to_discard(console):
    console.results = lambda n, cfg: ("Completed: Max Results", [log(i) for i in range(6000)])
    out = await client().run_search(ioc_query_filter("ip", ["10.0.0.1"]), START, END)
    assert out.logs == [] and out.capped and out.status == "Completed: Max Results"
    assert not any(e["messageType"] == "LogsRequest" for e in console.envelopes)
    assert len(console.removed) == 1


# ---- the caller's time budget is enforced INSIDE a search --------------------------------------------------------------------------------
async def test_a_search_gives_up_at_the_callers_deadline_and_still_removes_its_task(console):
    console.stuck = True  # the task never completes: without a deadline this would wait for task_timeout_s
    with pytest.raises(lc.BudgetExceeded):
        await client(task_timeout_s=60).run_search(
            ioc_query_filter("ip", ["10.0.0.1"]), START, END, deadline=time.monotonic() + 0.05
        )
    assert len(console.removed) == 1


async def test_reading_the_logs_stops_between_pages_at_the_deadline(console):
    c = client()
    sock = await c._ensure()
    with pytest.raises(lc.BudgetExceeded):
        await c._page(
            sock, "no-such-task", 400, time.monotonic() - 1
        )  # past the deadline: not even the first page is asked
    assert not any(e["messageType"] == "LogsRequest" for e in console.envelopes)


async def test_the_connector_refuses_to_start_a_search_after_its_deadline(console):
    c = lr()
    c._deadline = time.monotonic() - 1
    with pytest.raises(lc.BudgetExceeded):
        await c._search_window(START, END)
    assert console.searches == 0  # nothing was asked of the console
    c._deadline = time.monotonic() + 600
    assert len(await c._search_window(START, END)) == 3  # a deadline in the future changes nothing


async def test_stopping_exactly_at_the_limit_while_the_console_is_still_searching_counts_as_cut(console):
    console.results = lambda n, cfg: ("Completed: All Results", [log(i) for i in range(6000)])
    out = await client().run_search(ioc_query_filter("ip", ["10.0.0.1"]), START, END, max_logs=5000)
    assert len(out.logs) == 5000 and out.total == 5000  # the console had delivered exactly what we asked for ...
    assert out.status == "First Results" and out.capped  # ... but it was not finished, so there is more

    console.results = lambda n, cfg: ("Completed: All Results", [log(i) for i in range(300)])
    done = await client().run_search(ioc_query_filter("ip", ["10.0.0.1"]), START, END, max_logs=1000)
    assert len(done.logs) == 300 and not done.capped  # a task that finished below the limit is complete, not cut
    assert done.status == "Completed: All Results"
