"""Helpers for recursively removing sensitive values from payloads."""

from collections.abc import Mapping, Sequence
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any
from uuid import UUID

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


def json_safe(data: Any) -> Any:
    """Return a JSON-serializable copy of ``data``.

    Sanitized metadata and masked payloads are persisted in JSONField columns and
    may also be passed to JSON-backed event stores.  Framework objects such as
    Django ``User`` instances are not JSON serializable, so reduce common model
    objects to their primary key and fall back to a string representation for
    other custom objects.
    """
    if isinstance(data, Mapping):
        return {str(key): json_safe(value) for key, value in data.items()}

    if isinstance(data, tuple):
        return [json_safe(item) for item in data]

    if isinstance(data, list):
        return [json_safe(item) for item in data]

    # Avoid treating strings/bytes as generic Sequences.
    if isinstance(data, Sequence) and not isinstance(data, (str, bytes, bytearray)):
        return [json_safe(item) for item in data]

    if data is None or isinstance(data, (str, int, float, bool)):
        return data

    if isinstance(data, (datetime, date, time, Decimal, UUID)):
        return str(data)

    for attr in ("pk", "id"):
        value = getattr(data, attr, None)
        if value is not None and value is not data:
            return json_safe(value)

    return str(data)
