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
        from .providers import DjangoAnomalyEventStore, LoggingAlertDispatcher
        

        config = AnomalyConfig(rule_profiles=getattr(settings, "ANOMALY_RULE_PROFILES", {}))
        _anomaly_service = AnomalyDetectionService(
            flags=get_feature_flags(),
            event_store=DjangoAnomalyEventStore(),
            alert_dispatcher=LoggingAlertDispatcher(),
            config=config,
        )

    return _anomaly_service
