import hashlib
import json

from django.core.cache import cache

PREFIX = "anomaly_infra"
MAX_KEY_LEN = 220


def key(*parts: str) -> str:
    """Build a namespaced, cache-safe key without leaking long raw payloads."""
    raw = ":".join(str(part) for part in parts if part is not None)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    readable = "_".join(
        "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(part))[:32]
        for part in parts[:2]
        if part is not None
    )
    prefix = f"{PREFIX}:{readable}:" if readable else f"{PREFIX}:"
    return (prefix + digest)[:MAX_KEY_LEN]


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
