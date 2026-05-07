import json
from types import SimpleNamespace

import pytest
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.test import RequestFactory, override_settings

from anomaly_infra.config import AnomalyConfig
from anomaly_infra.constants import ANOMALY_DETECTION_ENABLED
from anomaly_infra.django.middleware import RequestAnomalyMiddleware
from anomaly_infra.django.models import AnomalyEvent
from anomaly_infra.django.request import build_event_payload, get_ip
from anomaly_infra.service import AnomalyDetectionService
from anomaly_infra.types import AnomalyDecision

from tests.conftest import DummyFlags


@pytest.mark.django_db
def test_anomaly_event_can_be_created_and_string_is_safe():
    event = AnomalyEvent.objects.create(
        anomaly_type="x",
        category="request",
        severity="low",
        risk_score=1,
        metadata={},
        masked_payload={},
    )
    assert event.pk
    assert str(event) == "AnomalyEvent<x:low>"
    assert "metadata" not in str(event)


@pytest.mark.django_db
def test_mark_resolved_sets_fields():
    event = AnomalyEvent.objects.create(anomaly_type="x", category="request", severity="low", risk_score=1)
    event.mark_resolved("done")
    event.refresh_from_db()
    assert event.resolved is True
    assert event.resolved_at is not None
    assert event.notes == "done"


def decision(anomaly_type="x", risk_score=50):
    return AnomalyDecision(
        anomaly_type=anomaly_type,
        category="request",
        severity="high",
        risk_score=risk_score,
        metadata={"access_token": "secret"},
        should_alert=False,
        action_taken="log",
    )


def test_build_event_payload_masks_payload_and_omits_raw_secrets(rf):
    request = rf.post("/api/v1/things/123", data={"password": "secret"})
    request.META["REMOTE_ADDR"] = "10.0.0.1"
    payload = build_event_payload(
        decision(), request=request, payload={"password": "secret", "nested": {"api_key": "secret"}}
    )
    assert payload["metadata"]["access_token"] == "***"
    assert payload["masked_payload"]["password"] == "***"
    assert payload["masked_payload"]["nested"]["api_key"] == "***"
    assert "secret" not in repr(payload)


@pytest.mark.django_db
def test_build_event_payload_uses_json_safe_user_id_and_metadata(rf):
    user = get_user_model().objects.create_user(username="sam")
    request = rf.get("/api/v1/things/123")
    request.user = user

    payload = build_event_payload(
        decision(),
        request=request,
        user=user,
        payload={"actor": user},
    )

    assert payload["user_id"] == user.pk
    assert "user" not in payload
    assert payload["masked_payload"]["actor"] == user.pk
    json.dumps(payload)
    event = AnomalyEvent.objects.create(**payload)
    assert event.user == user


def test_get_ip_uses_remote_addr_by_default(rf):
    request = rf.get("/", HTTP_X_FORWARDED_FOR="203.0.113.1, 10.0.0.1", REMOTE_ADDR="10.0.0.2")
    assert get_ip(request) == "10.0.0.2"


@override_settings(ANOMALY_TRUST_X_FORWARDED_FOR=True)
def test_get_ip_uses_x_forwarded_for_only_when_enabled(rf):
    request = rf.get("/", HTTP_X_FORWARDED_FOR="203.0.113.1, 10.0.0.1", REMOTE_ADDR="10.0.0.2")
    assert get_ip(request) == "203.0.113.1"


class RecordingService(AnomalyDetectionService):
    def __init__(self, enabled=True):
        super().__init__(
            flags=DummyFlags({ANOMALY_DETECTION_ENABLED: enabled}),
            config=AnomalyConfig(
                {
                    "repeated_validation_failures": {"risk_score": 10, "severity": "low", "category": "request"},
                    "repeated_forbidden_access": {"risk_score": 20, "severity": "medium", "category": "permission"},
                    "burst_sensitive_endpoint_access": {"risk_score": 60, "severity": "high", "category": "request"},
                    "cross_tenant_access_attempt": {"risk_score": 50, "severity": "high", "category": "permission"},
                    "path_probing": {"risk_score": 60, "severity": "high", "category": "permission"},
                }
            ),
        )
        self.records = []

    def record(self, decision, *, payload=None):
        self.records.append((decision, payload))
        return SimpleNamespace(id="1")


def install_service(monkeypatch, service):
    monkeypatch.setattr("anomaly_infra.django.middleware.get_anomaly_service", lambda: service)
    return service


def call_middleware(path, response, monkeypatch, service, method="GET", user=None, **meta):
    rf = RequestFactory()
    request = getattr(rf, method.lower())(path, **meta)
    if user is not None:
        request.user = user
    install_service(monkeypatch, service)
    mw = RequestAnomalyMiddleware(lambda req: response)
    return mw(request), service


def test_middleware_does_nothing_when_global_detection_flag_disabled(monkeypatch):
    service = RecordingService(enabled=False)
    call_middleware("/api/v1/account/login", HttpResponse(status=400), monkeypatch, service, method="POST")
    assert service.records == []


@override_settings(ANOMALY_VALIDATION_FAILURE_THRESHOLD=2, ANOMALY_VALIDATION_FAILURE_WINDOW_SECONDS=120)
def test_middleware_records_validation_failure_after_threshold(monkeypatch):
    service = RecordingService()
    for _ in range(2):
        call_middleware("/api/v1/items", HttpResponse(status=400), monkeypatch, service)
    assert service.records[-1][0].anomaly_type == "repeated_validation_failures"


@override_settings(ANOMALY_VALIDATION_FAILURE_THRESHOLD=2, ANOMALY_VALIDATION_FAILURE_WINDOW_SECONDS=120)
def test_middleware_records_forbidden_access_after_threshold(monkeypatch):
    service = RecordingService()
    for _ in range(2):
        call_middleware("/api/v1/items", HttpResponse(status=403), monkeypatch, service)
    assert service.records[-1][0].anomaly_type == "repeated_forbidden_access"


@override_settings(ANOMALY_BURST_THRESHOLD=2, ANOMALY_SENSITIVE_PREFIXES=("/api/v1/account/",))
def test_middleware_records_burst_after_threshold(monkeypatch):
    service = RecordingService()
    for _ in range(2):
        call_middleware("/api/v1/account/login", HttpResponse(status=200), monkeypatch, service, method="POST")
    assert service.records[-1][0].anomaly_type == "burst_sensitive_endpoint_access"


def test_middleware_records_tenant_mismatch_without_tenant_model(monkeypatch):
    service = RecordingService()
    response = HttpResponse(status=200)
    rf = RequestFactory()
    request = rf.get("/api/v1/items", HTTP_X_TENANT="a")
    request.tenant = SimpleNamespace(id="b", name="Tenant B")
    install_service(monkeypatch, service)
    RequestAnomalyMiddleware(lambda req: response)(request)
    assert service.records[-1][0].anomaly_type == "cross_tenant_access_attempt"


def test_middleware_does_not_crash_with_anonymous_or_missing_user(monkeypatch):
    service = RecordingService()
    call_middleware("/api/v1/items", HttpResponse(status=200), monkeypatch, service)
    anon = SimpleNamespace(is_authenticated=False)
    call_middleware("/api/v1/items", HttpResponse(status=200), monkeypatch, service, user=anon)


def test_middleware_does_not_crash_with_missing_status_code(monkeypatch):
    service = RecordingService()
    call_middleware("/api/v1/items", object(), monkeypatch, service)


def test_service_helper_import_does_not_cause_app_registry_not_ready():
    from anomaly_infra.django import service

    assert hasattr(service, "get_anomaly_service")


@pytest.mark.django_db(transaction=True, databases=["anomaly_primary", "anomaly_events"])
def test_django_event_store_persists_inside_rolled_back_transaction():
    from django.db import transaction

    from anomaly_infra.django.providers import DjangoAnomalyEventStore

    store = DjangoAnomalyEventStore(
        database="anomaly_primary",
        independent_database_alias="anomaly_events",
    )

    with pytest.raises(RuntimeError):
        with transaction.atomic(using="anomaly_primary"):
            store.save({"anomaly_type": "x", "category": "request", "severity": "low", "risk_score": 1})
            raise RuntimeError("roll back business transaction")

    assert AnomalyEvent.objects.using("anomaly_primary").filter(anomaly_type="x").count() == 1
