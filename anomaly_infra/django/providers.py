from __future__ import annotations

import logging

from anomaly_infra.interfaces import AlertDispatcher, AnomalyEventStore
from anomaly_infra.sanitizer import mask_sensitive

logger = logging.getLogger(__name__)


class DjangoAnomalyEventStore(AnomalyEventStore):
    def save(self, payload: dict):
        from .models import AnomalyEvent

        return AnomalyEvent.objects.create(**payload)


class LoggingAlertDispatcher(AlertDispatcher):
    def dispatch(self, event_id: str, payload: dict | None = None):
        safe_payload = mask_sensitive(payload or {})
        # Keep the log compact and sanitized; never emit raw request bodies.
        logger.warning(
            "anomaly_alert_dispatched",
            extra={
                "event_id": event_id,
                "anomaly_type": safe_payload.get("anomaly_type"),
                "severity": safe_payload.get("severity"),
                "risk_score": safe_payload.get("risk_score"),
            },
        )
