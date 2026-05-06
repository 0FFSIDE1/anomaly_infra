import hashlib
import json

from django.core.cache import cache

PREFIX = "anomaly"


def key(*parts: str) -> str:
    safe = [str(part) for part in parts if part is not None]
    return f"{PREFIX}:" + ":".join(safe)


def increment_counter(counter_key: str, ttl_seconds: int) -> int:
    value = cache.get(counter_key)

    if value is None:
        cache.set(counter_key, 1, timeout=ttl_seconds)
        return 1

    try:
        return cache.incr(counter_key)
    except ValueError:
        next_value = int(value) + 1
        cache.set(counter_key, next_value, timeout=ttl_seconds)
        return next_value


def payload_hash(payload: dict) -> str:
    serialized = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()