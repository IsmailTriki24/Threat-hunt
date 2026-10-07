import logging
import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.logging import bind_log_context, clear_log_context
from app.core.metrics import HTTP_LATENCY, HTTP_REQUESTS

log = logging.getLogger("app.http")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # API only serves JSON; lock everything down.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
}


class BodyLimitMiddleware:
    """Rejects request bodies above `max_bytes`, counting streamed (chunked) bodies too."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            await self._reject(send)
            return
        received = 0
        too_large = False

        async def limited_receive() -> Message:
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    too_large = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        started = False

        async def guarded_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                if too_large:
                    message = {**message, "status": 413}
                started = True
            await send(message)

        await self.app(scope, limited_receive, guarded_send)
        if too_large and not started:
            await self._reject(send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"error":{"code":"payload_too_large","message":"Request body too large"}}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})


def install_http_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def request_context(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        # Never trust a client-supplied request id for log correlation beyond a sane charset/length.
        supplied = request.headers.get("x-request-id", "")
        request_id = supplied if supplied.isalnum() and len(supplied) <= 64 else uuid.uuid4().hex
        request.state.request_id = request_id
        clear_log_context()
        bind_log_context(request_id=request_id)
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
        finally:
            elapsed = time.perf_counter() - started
            route = request.scope.get("route")
            path_label = getattr(route, "path", "unmatched")
            HTTP_REQUESTS.labels(request.method, path_label, str(status)).inc()
            HTTP_LATENCY.labels(request.method, path_label).observe(elapsed)
            if path_label not in ("/health", "/metrics"):
                log.info(
                    "request",
                    extra={
                        "method": request.method,
                        "path": request.url.path,
                        "status": status,
                        "duration_ms": round(elapsed * 1000, 1),
                    },
                )
        response.headers["X-Request-ID"] = request_id
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.url.path in ("/docs", "/redoc", "/openapi.json"):
            del response.headers["Content-Security-Policy"]
        return response
