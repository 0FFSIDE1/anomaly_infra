from __future__ import annotations

"""Alert dispatchers and adapters for anomaly-infra."""

import importlib
import logging
from collections.abc import Mapping
from typing import Any

from .interfaces import AlertDispatcher
from .sanitizer import json_safe, mask_sensitive

logger = logging.getLogger(__name__)

ALERT_INFRA_SEVERITIES = frozenset({"info", "warning", "error", "critical"})
ANOMALY_TO_ALERT_SEVERITY = {
    "low": "info",
    "medium": "warning",
    "high": "error",
    "critical": "critical",
    "info": "info",
    "warning": "warning",
    "error": "error",
}
SAFE_METADATA_KEYS = frozenset(
    {
        "event_id",
        "anomaly_type",
        "severity",
        "risk_score",
        "user_id",
        "tenant",
        "request_id",
        "correlation_id",
        "action",
        "resource",
        "context",
    }
)
UNSAFE_CONTEXT_KEYS = frozenset(
    {
        "body",
        "raw_body",
        "request_body",
        "payload",
        "raw_payload",
        "masked_payload",
        "headers",
        "cookies",
    }
)


class LoggingAlertDispatcher(AlertDispatcher):
    """Compact sanitized logging fallback for anomaly alerts."""

    def dispatch(self, event_id: str, payload: dict | None = None):
        safe_payload = mask_sensitive(payload or {})
        logger.warning(
            "anomaly_alert_dispatched",
            extra={
                "event_id": event_id,
                "anomaly_type": safe_payload.get("anomaly_type"),
                "severity": safe_payload.get("severity"),
                "risk_score": safe_payload.get("risk_score"),
            },
        )


class AlertInfraAnomalyDispatcher(AlertDispatcher):
    """Adapt anomaly-infra alert events to the optional alert_infra package.

    The adapter keeps alert_infra optional, performs anomaly-infra redaction before
    constructing alerts, and delegates async behavior to alert_infra's Django or
    dispatcher configuration instead of creating anomaly-specific Celery tasks.
    """

    def __init__(
        self,
        *,
        dispatcher: Any | None = None,
        enabled: bool | None = None,
        fail_silently: bool | None = None,
        fallback: AlertDispatcher | None = None,
        prefer_django: bool = True,
    ):
        self.dispatcher = dispatcher
        self.enabled = enabled
        self.fail_silently = fail_silently
        self.fallback = fallback or LoggingAlertDispatcher()
        self.prefer_django = prefer_django

    def dispatch(self, event_id: str, payload: dict | None = None):
        safe_payload = mask_sensitive(payload or {})
        alert_fields = build_alert_fields(event_id, safe_payload)

        if not self._enabled():
            self._log_delivery(alert_fields, status="disabled")
            return self.fallback.dispatch(event_id, safe_payload)

        try:
            alert = self._build_alert(alert_fields)
            if self.dispatcher is not None:
                result = self._dispatch_with_injected_dispatcher(alert)
                self._log_delivery(alert_fields, result=result)
                return result

            send_alert = self._get_django_send_alert()
            if send_alert is not None:
                result = send_alert(alert)
                self._log_delivery(alert_fields, result=result)
                return result

            dispatcher = self._build_default_alert_infra_dispatcher()
            result = self._call_dispatcher(dispatcher, alert)
            self._log_delivery(alert_fields, result=result)
            return result
        except ModuleNotFoundError as exc:
            if exc.name and exc.name.startswith("alert_infra"):
                self._log_delivery(alert_fields, status="missing")
                return self.fallback.dispatch(event_id, safe_payload)
            raise
        except Exception as exc:
            self._log_delivery(alert_fields, status="failed")
            if self._fail_silently():
                logger.warning(
                    "anomaly_alert_infra_delivery_failed",
                    extra={
                        "event_id": alert_fields["metadata"].get("event_id"),
                        "anomaly_type": alert_fields["metadata"].get("anomaly_type"),
                        "severity": alert_fields.get("severity"),
                        "risk_score": alert_fields["metadata"].get("risk_score"),
                        "delivery_status": "fallback",
                        "failed_transports": _failed_transport_names(exc),
                    },
                )
                return self.fallback.dispatch(event_id, safe_payload)
            raise

    def _enabled(self) -> bool:
        if self.enabled is not None:
            return bool(self.enabled)
        return bool(_anomaly_infra_setting("ALERT_INFRA_ENABLED", True))

    def _fail_silently(self) -> bool:
        if self.fail_silently is not None:
            return bool(self.fail_silently)
        return bool(_anomaly_infra_setting("ALERT_FAIL_SILENTLY", True))

    def _build_alert(self, alert_fields: dict[str, Any]) -> Any:
        alert_module = importlib.import_module("alert_infra")
        alert_class = getattr(alert_module, "Alert")
        return alert_class(**alert_fields)

    def _get_django_send_alert(self):
        if not self.prefer_django or not _django_settings_configured():
            return None
        try:
            django_module = importlib.import_module("alert_infra.django")
        except ModuleNotFoundError as exc:
            if exc.name and exc.name.startswith("alert_infra"):
                return None
            raise
        return getattr(django_module, "send_alert", None)

    def _build_default_alert_infra_dispatcher(self):
        alert_module = importlib.import_module("alert_infra")
        dispatcher_class = getattr(alert_module, "AlertDispatcher")
        return dispatcher_class()

    def _dispatch_with_injected_dispatcher(self, alert: Any):
        return self._call_dispatcher(self.dispatcher, alert)

    @staticmethod
    def _call_dispatcher(dispatcher: Any, alert: Any):
        if hasattr(dispatcher, "dispatch"):
            return dispatcher.dispatch(alert)
        if hasattr(dispatcher, "send"):
            return dispatcher.send(alert)
        raise TypeError("alert_infra dispatcher must provide dispatch(alert) or send(alert)")

    @staticmethod
    def _log_delivery(
        alert_fields: dict[str, Any], *, result: Any | None = None, status: str | None = None
    ) -> None:
        metadata = alert_fields["metadata"]
        logger.warning(
            "anomaly_alert_infra_dispatched",
            extra={
                "event_id": metadata.get("event_id"),
                "anomaly_type": metadata.get("anomaly_type"),
                "severity": alert_fields.get("severity"),
                "risk_score": metadata.get("risk_score"),
                "delivery_status": status or _delivery_status(result),
                "failed_transports": _failed_transport_names(result),
            },
        )


def build_alert_fields(event_id: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Build sanitized alert_infra.Alert kwargs from an anomaly payload."""

    safe_payload = mask_sensitive(dict(payload or {}))
    anomaly_type = str(safe_payload.get("anomaly_type") or "unknown")
    severity = map_alert_severity(safe_payload.get("severity"), safe_payload.get("risk_score"))
    metadata = build_alert_metadata(event_id, safe_payload, severity)
    tenant = metadata.get("tenant")
    tags = ["anomaly", anomaly_type]
    if tenant:
        tags.append(str(tenant))

    risk_score = metadata.get("risk_score")
    message = f"Anomaly {anomaly_type!r} detected"
    if risk_score is not None:
        message = f"{message} with risk score {risk_score}."
    else:
        message = f"{message}."

    return {
        "title": f"Anomaly detected: {anomaly_type}",
        "message": message,
        "severity": severity,
        "source": "anomaly_infra",
        "tags": tags,
        "metadata": metadata,
    }


def build_alert_metadata(event_id: str, safe_payload: Mapping[str, Any], severity: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "event_id": event_id,
        "anomaly_type": safe_payload.get("anomaly_type"),
        "severity": severity,
    }
    for key in SAFE_METADATA_KEYS - {"event_id", "anomaly_type", "severity", "context"}:
        if key in safe_payload and safe_payload[key] is not None:
            metadata[key] = safe_payload[key]

    context = _safe_context(safe_payload.get("context"))
    if context:
        metadata["context"] = context

    return json_safe(mask_sensitive(metadata))


def map_alert_severity(severity: Any = None, risk_score: Any = None) -> str:
    normalized = str(severity or "").strip().lower()
    if normalized in ALERT_INFRA_SEVERITIES:
        return normalized
    if normalized in ANOMALY_TO_ALERT_SEVERITY:
        return ANOMALY_TO_ALERT_SEVERITY[normalized]

    try:
        score = int(risk_score)
    except (TypeError, ValueError):
        score = 0

    if score >= 90:
        return "critical"
    if score >= 70:
        return "error"
    if score >= 40:
        return "warning"
    return "info"


def _safe_context(value: Any) -> Any:
    if not isinstance(value, Mapping):
        return None
    return {
        key: mask_sensitive(context_value)
        for key, context_value in value.items()
        if str(key).lower().replace("-", "_") not in UNSAFE_CONTEXT_KEYS
    }


def _anomaly_infra_setting(name: str, default: Any = None) -> Any:
    try:
        from django.conf import settings
    except Exception:
        return default
    if not getattr(settings, "configured", False):
        return default
    config = getattr(settings, "ANOMALY_INFRA", {}) or {}
    if isinstance(config, Mapping) and name in config:
        return config[name]
    return getattr(settings, name, default)


def _django_settings_configured() -> bool:
    try:
        from django.conf import settings
    except Exception:
        return False
    return bool(getattr(settings, "configured", False))


def _delivery_status(result: Any) -> str:
    if result is None:
        return "unknown"
    status = getattr(result, "status", None)
    if status is not None:
        return str(status)
    success = getattr(result, "success", None)
    if success is not None:
        return "success" if success else "failed"
    return "sent"


def _failed_transport_names(result: Any) -> list[str]:
    names = getattr(result, "failed_transports", None)
    if names is None:
        names = getattr(result, "failed_transport_names", None)
    if names is None:
        failures = getattr(result, "failures", None)
        if isinstance(failures, Mapping):
            names = failures.keys()
    if names is None:
        transport_name = getattr(result, "transport", None) or getattr(result, "transport_name", None)
        names = [transport_name] if transport_name else []
    return [str(name) for name in names if name]
