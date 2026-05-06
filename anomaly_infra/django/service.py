# anomaly_infra/django/service.py

from django.conf import settings

from anomaly_infra.config import AnomalyConfig
from anomaly_infra.service import AnomalyDetectionService
from feature_flag_infra.django.service import get_feature_flags

from .providers import DjangoAnomalyEventStore, LoggingAlertDispatcher


_anomaly_service = None


def get_anomaly_service() -> AnomalyDetectionService:
    global _anomaly_service

    if _anomaly_service is None:
        config = AnomalyConfig(
            rule_profiles=getattr(settings, "ANOMALY_RULE_PROFILES", {}),
        )

        _anomaly_service = AnomalyDetectionService(
            flags=get_feature_flags(),
            event_store=DjangoAnomalyEventStore(),
            alert_dispatcher=LoggingAlertDispatcher(),
            config=config,
        )

    return _anomaly_service