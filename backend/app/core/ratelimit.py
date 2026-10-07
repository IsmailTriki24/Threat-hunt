import logging
import time
from collections import defaultdict

from fastapi import Request
from redis.asyncio import Redis

from app.core.errors import AppError

log = logging.getLogger("app.ratelimit")


class RateLimited(AppError):
    status_code = 429
    code = "rate_limited"


_local: dict[str, tuple[int, float]] = defaultdict(lambda: (0, 0.0))


async def hit(redis: Redis, key: str, limit: int, window_s: int) -> tuple[bool, int]:
    """Fixed-window counter. Returns (allowed, retry_after_seconds).

    Uses Redis; if Redis is unreachable falls back to a per-process counter (fail-soft, still limiting).
    """
    bucket = f"rl:{key}:{int(time.time()) // window_s}"
    retry_after = window_s - int(time.time()) % window_s
    try:
        pipe = redis.pipeline()
        pipe.incr(bucket)
        pipe.expire(bucket, window_s + 1)
        count = int((await pipe.execute())[0])
    except Exception:
        log.warning("rate limiter falling back to local counters")
        count, expires = _local[bucket]
        now = time.time()
        if expires < now:
            count, expires = 0, now + window_s
        _local[bucket] = (count + 1, expires)
        count += 1
    return count <= limit, retry_after


async def enforce(request: Request, key: str, limit: int, window_s: int) -> None:
    allowed, retry_after = await hit(request.app.state.redis, key, limit, window_s)
    if not allowed:
        exc = RateLimited(f"Too many requests; retry in {retry_after}s")
        raise exc


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"
