from __future__ import annotations
import logging
import sys
import types
from dataclasses import dataclass

import pytest

from anomaly_infra.alerts import (
    AlertInfraAnomalyDispatcher,
    AlertInfraDeliveryFailed,
    LoggingAlertDispatcher,
    build_alert_fields,
    map_alert_severity,
)


@dataclass
class FakeAlert:
    title: str
    message: str
    severity: str = "error"
    source: str | None = None
    tags: tuple[str, ...] = ()
    metadata: dict | None = None
    correlation_id: str | None = None
    request_id: str | None = None


class FakeDeliveryResult:
    def __init__(self, *, sent=("recording",), failed=None):
        self.sent = sent
        self.failed = failed or {}

    @property
    def ok(self):
        return not self.failed


class RecordingAlertDispatcher:
    def __init__(self):
        self.alerts = []

    def send(self, alert):
        self.alerts.append(alert)
        return FakeDeliveryResult()


@pytest.fixture
def fake_alert_infra(monkeypatch):
    module = types.ModuleType("alert_infra")
    module.Alert = FakeAlert
    module.AlertDispatcher = RecordingAlertDispatcher
    monkeypatch.setitem(sys.modules, "alert_infra", module)
    monkeypatch.delitem(sys.modules, "alert_infra.django", raising=False)
    return module


def test_logging_alert_dispatcher_logs_safe_compact_data(caplog):
    caplog.set_level(logging.WARNING)

    LoggingAlertDispatcher().dispatch(
        "event-1",
        {
            "anomaly_type": "invoice_total_mismatch",
            "severity": "warning",
            "risk_score": 75,
            "authorization": "Bearer secret",
            "cookie": "session=secret",
        },
    )

    record = caplog.records[-1]
    assert record.message == "anomaly_alert_dispatched"
    assert record.event_id == "event-1"
    assert record.anomaly_type == "invoice_total_mismatch"
    assert record.severity == "warning"
    assert record.risk_score == 75
    assert "Bearer secret" not in caplog.text
    assert "session=secret" not in caplog.text


def test_alert_infra_dispatcher_builds_alert_and_plain_python_injection_masks_sensitive(fake_alert_infra):
    injected = RecordingAlertDispatcher()
    dispatcher = AlertInfraAnomalyDispatcher(dispatcher=injected, prefer_django=False)

    dispatcher.dispatch(
        "event-2",
        {
            "anomaly_type": "invoice_total_mismatch",
            "severity": "warning",
            "risk_score": 75,
            "user_id": 123,
            "tenant": "tenant-a",
            "request_id": "req-1",
            "authorization": "Bearer secret",
            "api_key": "key-secret",
            "context": {"action": "pay", "token": "secret", "body": {"raw": "do-not-send"}},
        },
    )

    alert = injected.alerts[-1]
    assert alert.title == "Anomaly detected: invoice_total_mismatch"
    assert alert.severity == "warning"
    assert alert.source == "anomaly_infra"
    assert alert.tags == ("anomaly", "invoice_total_mismatch", "tenant-a")
    assert alert.metadata["event_id"] == "event-2"
    assert alert.metadata["user_id"] == 123
    assert "authorization" not in alert.metadata
    assert "api_key" not in alert.metadata
    assert alert.metadata["context"]["token"] == "***"
    assert "body" not in alert.metadata["context"]
    assert "Bearer secret" not in repr(alert.metadata)
    assert "key-secret" not in repr(alert.metadata)
    assert "do-not-send" not in repr(alert.metadata)


@pytest.mark.parametrize(
    ("risk_score", "expected"),
    [(95, "critical"), (90, "critical"), (75, "error"), (70, "error"), (55, "warning"), (40, "warning"), (39, "info")],
)
def test_risk_score_maps_to_alert_infra_severity(risk_score, expected):
    assert map_alert_severity(None, risk_score) == expected


@pytest.mark.parametrize(
    ("explicit", "expected"),
    [("critical", "critical"), ("error", "error"), ("warning", "warning"), ("info", "info"), ("high", "error"), ("medium", "warning"), ("low", "info")],
)
def test_existing_explicit_severity_is_respected(explicit, expected):
    assert map_alert_severity(explicit, 10) == expected


def test_missing_alert_infra_falls_back_to_logging(monkeypatch, caplog):
    monkeypatch.delitem(sys.modules, "alert_infra", raising=False)
    monkeypatch.delitem(sys.modules, "alert_infra.django", raising=False)
    caplog.set_level(logging.WARNING)

    dispatcher = AlertInfraAnomalyDispatcher(prefer_django=False)
    dispatcher.dispatch("event-3", {"anomaly_type": "x", "risk_score": 91, "authorization": "Bearer secret"})

    assert "anomaly_alert_dispatched" in caplog.text
    assert "Bearer secret" not in caplog.text


def test_delivery_failure_does_not_crash_when_fail_silently_enabled(fake_alert_infra, caplog):
    class FailingDispatcher:
        def send(self, alert):
            raise RuntimeError("slack failed")

    caplog.set_level(logging.WARNING)
    dispatcher = AlertInfraAnomalyDispatcher(
        dispatcher=FailingDispatcher(), fail_silently=True, prefer_django=False
    )

    dispatcher.dispatch("event-4", {"anomaly_type": "x", "risk_score": 91, "token": "secret"})

    assert "anomaly_alert_infra_delivery_failed" in caplog.text
    assert "anomaly_alert_dispatched" in caplog.text
    assert "secret" not in caplog.text


def test_delivery_failure_raises_when_fail_silently_disabled(fake_alert_infra):
    class FailingDispatcher:
        def send(self, alert):
            raise RuntimeError("delivery failed")

    dispatcher = AlertInfraAnomalyDispatcher(
        dispatcher=FailingDispatcher(), fail_silently=False, prefer_django=False
    )

    with pytest.raises(RuntimeError, match="delivery failed"):
        dispatcher.dispatch("event-5", {"anomaly_type": "x", "risk_score": 91})


def test_django_send_alert_path_is_used_when_available(monkeypatch, fake_alert_infra, settings):
    sent = []
    django_module = types.ModuleType("alert_infra.django")

    def send_alert(**kwargs):
        sent.append(kwargs)
        return FakeDeliveryResult(sent=("noop",))

    django_module.send_alert = send_alert
    monkeypatch.setitem(sys.modules, "alert_infra.django", django_module)

    dispatcher = AlertInfraAnomalyDispatcher()
    dispatcher.dispatch("event-6", {"anomaly_type": "x", "risk_score": 91})

    assert sent
    assert sent[-1]["title"] == "Anomaly detected: x"
    assert sent[-1]["metadata"]["event_id"] == "event-6"


def test_build_alert_fields_excludes_raw_payloads_and_sensitive_values():
    fields = build_alert_fields(
        "event-7",
        {
            "anomaly_type": "x",
            "risk_score": 91,
            "payload": {"authorization": "Bearer secret"},
            "raw_payload": "raw secret",
            "session_id": "session-secret",
            "csrf_token": "csrf-secret",
            "action": "review",
            "resource": "invoice",
        },
    )

    metadata = fields["metadata"]
    assert metadata["action"] == "review"
    assert metadata["resource"] == "invoice"
    assert "payload" not in metadata
    assert "raw_payload" not in metadata
    assert "session_id" not in metadata
    assert "csrf_token" not in metadata
    assert "Bearer secret" not in repr(fields)
    assert "raw secret" not in repr(fields)
    assert "session-secret" not in repr(fields)
    assert "csrf-secret" not in repr(fields)


def test_alert_infra_async_delivery_is_delegated_to_send_alert(monkeypatch, fake_alert_infra, settings):
    calls = []
    django_module = types.ModuleType("alert_infra.django")
    django_module.send_alert = lambda **kwargs: calls.append(kwargs) or FakeDeliveryResult(sent=("celery",))
    monkeypatch.setitem(sys.modules, "alert_infra.django", django_module)

    AlertInfraAnomalyDispatcher().dispatch("event-8", {"anomaly_type": "async", "risk_score": 70})

    assert len(calls) == 1


def test_failed_delivery_result_falls_back_when_fail_silently_enabled(fake_alert_infra, caplog):
    class PartiallyFailingDispatcher:
        def send(self, alert):
            return FakeDeliveryResult(sent=("email.smtp",), failed={"slack": "AlertDeliveryError"})

    caplog.set_level(logging.WARNING)
    dispatcher = AlertInfraAnomalyDispatcher(
        dispatcher=PartiallyFailingDispatcher(), fail_silently=True, prefer_django=False
    )

    result = dispatcher.dispatch("event-9", {"anomaly_type": "x", "risk_score": 91, "api_key": "secret"})

    assert result.failed == {"slack": "AlertDeliveryError"}
    assert "anomaly_alert_infra_delivery_failed" in caplog.text
    assert "anomaly_alert_dispatched" in caplog.text
    assert "secret" not in caplog.text


def test_failed_delivery_result_raises_when_fail_silently_disabled(fake_alert_infra):
    class FailingResultDispatcher:
        def send(self, alert):
            return FakeDeliveryResult(sent=(), failed={"telegram": "AlertDeliveryError"})

    dispatcher = AlertInfraAnomalyDispatcher(
        dispatcher=FailingResultDispatcher(), fail_silently=False, prefer_django=False
    )

    with pytest.raises(AlertInfraDeliveryFailed, match="telegram"):
        dispatcher.dispatch("event-10", {"anomaly_type": "x", "risk_score": 91})
