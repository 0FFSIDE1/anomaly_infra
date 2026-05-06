"""Helpers for recursively removing sensitive values from payloads."""

from collections.abc import Mapping, Sequence
from typing import Any

from .constants import MASKED_VALUE

SENSITIVE_KEYS = {
    "password",
    "token",
    "refresh",
    "access",
    "authorization",
    "secret",
    "api_key",
    "card",
    "cvv",
    "pin",
    "cookie",
    "session",
    "csrf",
    "set-cookie",
}


def is_sensitive_key(key: Any) -> bool:
    """Return True when a key name likely contains a secret."""
    normalized = str(key).lower().replace("-", "_")
    return any(fragment.replace("-", "_") in normalized for fragment in SENSITIVE_KEYS)


def mask_sensitive(data: Any) -> Any:
    """Return a deep sanitized copy of ``data`` without mutating the input."""
    if isinstance(data, Mapping):
        return {
            key: MASKED_VALUE if is_sensitive_key(key) else mask_sensitive(value)
            for key, value in data.items()
        }

    if isinstance(data, tuple):
        return tuple(mask_sensitive(item) for item in data)

    if isinstance(data, list):
        return [mask_sensitive(item) for item in data]

    # Avoid treating strings/bytes as generic Sequences.
    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
        return [mask_sensitive(item) for item in data]

    return data
