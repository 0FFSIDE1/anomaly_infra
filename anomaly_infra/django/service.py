from __future__ import annotations

"""Django service factory for anomaly-infra.

This module intentionally avoids importing models/providers at import time so it
can be imported during Django startup without AppRegistryNotReady surprises.
"""

from django.conf import settings

from anomaly_infra.config import AnomalyConfig

_anomaly_service = None


def reset_anomaly_service() -> None:
    """Clear the cached singleton; primarily useful for tests."""
    global _anomaly_service
    _anomaly_service = None


def get_anomaly_service() -> AnomalyDetectionService:
    global _anomaly_service

    if _anomaly_service is None:
        from feature_flag_infra.django.service import get_feature_flags
        from anomaly_infra.service import AnomalyDetectionService
        from .providers import DjangoAnomalyEventStore

        config = AnomalyConfig(rule_profiles=getattr(settings, "ANOMALY_RULE_PROFILES", {}))
        _anomaly_service = AnomalyDetectionService(
            flags=get_feature_flags(),
            event_store=DjangoAnomalyEventStore(),
            alert_dispatcher=_build_alert_dispatcher(),
            config=config,
        )

    return _anomaly_service


def _anomaly_infra_settings() -> dict:
    value = getattr(settings, "ANOMALY_INFRA", {}) or {}
    return value if isinstance(value, dict) else {}


def _build_alert_dispatcher():
    from anomaly_infra.alerts import AlertInfraAnomalyDispatcher, LoggingAlertDispatcher

    config = _anomaly_infra_settings()
    dispatcher_name = str(config.get("ALERT_DISPATCHER", "alert_infra")).lower()
    if dispatcher_name in {"logging", "log"}:
        return LoggingAlertDispatcher()
    return AlertInfraAnomalyDispatcher(
        enabled=config.get("ALERT_INFRA_ENABLED"),
        fail_silently=config.get("ALERT_FAIL_SILENTLY"),
        fallback=LoggingAlertDispatcher(),
    )
