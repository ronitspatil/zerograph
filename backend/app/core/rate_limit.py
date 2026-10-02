import hashlib
import time
from functools import lru_cache

from fastapi import HTTPException
from redis import Redis
from redis.exceptions import RedisError

from app.core.config import get_settings

SCRIPT = """
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], 61) end
return n
"""


@lru_cache
def rate_client() -> Redis:
    return Redis.from_url(get_settings().redis_url, socket_timeout=2, socket_connect_timeout=2)


def enforce_rate_limit(tenant: str, subject: str) -> None:
    settings = get_settings()
    if settings.environment == "test":
        return
    digest = hashlib.sha256(f"{tenant}\0{subject}".encode()).hexdigest()
    key = f"zg:rate:{digest}:{int(time.time()) // 60}"
    try:
        requests = rate_client().eval(SCRIPT, 1, key)
        if requests > 120:
            raise HTTPException(429, "Request rate exceeded", headers={"Retry-After": "60"})
    except RedisError as exc:
        if settings.environment == "production":
            raise HTTPException(503, "Authentication rate limiter unavailable") from exc
