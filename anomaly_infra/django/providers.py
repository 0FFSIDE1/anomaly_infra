from anomaly_infra.interfaces import AlertDispatcher, AnomalyEventStore

from .models import AnomalyEvent


class DjangoAnomalyEventStore(AnomalyEventStore):
    def save(self, payload: dict) -> AnomalyEvent:
        return AnomalyEvent.objects.create(**payload)


class LoggingAlertDispatcher(AlertDispatcher):
    def dispatch(self, event_id: str, payload: dict | None = None):
        import logging

        logger = logging.getLogger(__name__)
        logger.warning(
            "anomaly_alert_dispatched",
            extra={
                "event_id": event_id,
                "payload": payload or {},
            },
        )