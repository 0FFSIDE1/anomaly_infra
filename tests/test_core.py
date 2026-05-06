import pytest

from anomaly_infra.config import AnomalyConfig
from anomaly_infra.constants import (
    ANOMALY_ALERTING_ENABLED,
    ANOMALY_BLOCKING_ENABLED,
    CATEGORY_BUSINESS,
    CATEGORY_REQUEST,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
)
from anomaly_infra.service import AnomalyDetectionService
from anomaly_infra.types import RuleProfile

from conftest import DummyFlags


class Store:
    def __init__(self):
        self.saved = []

    def save(self, payload):
        self.saved.append(payload)
        return type("Event", (), {"id": "event-1"})()


class Dispatcher:
    def __init__(self):
        self.dispatched = []

    def dispatch(self, event_id, payload=None):
        self.dispatched.append((event_id, payload))


def test_evaluate_returns_default_profile_for_unknown_anomaly_type():
    decision = AnomalyDetectionService().evaluate("unknown")
    assert decision.risk_score == 30
    assert decision.severity == "medium"
    assert decision.category == CATEGORY_REQUEST


def test_evaluate_uses_configured_rule_profile_overrides():
    svc = AnomalyDetectionService(
        config=AnomalyConfig({"unknown": {"risk_score": 91, "severity": SEVERITY_CRITICAL, "category": CATEGORY_BUSINESS}})
    )
    decision = svc.evaluate("unknown")
    assert decision.risk_score == 91
    assert decision.severity == SEVERITY_CRITICAL
    assert decision.category == CATEGORY_BUSINESS


@pytest.mark.parametrize("score", [-1, 101])
def test_invalid_rule_profile_risk_score_out_of_range_fails(score):
    with pytest.raises(ValueError):
        AnomalyConfig({"bad": {"risk_score": score, "severity": SEVERITY_HIGH, "category": CATEGORY_REQUEST}})


def test_invalid_severity_fails():
    with pytest.raises(ValueError):
        AnomalyConfig({"bad": {"risk_score": 50, "severity": "urgent", "category": CATEGORY_REQUEST}})


def test_invalid_category_fails():
    with pytest.raises(ValueError):
        AnomalyConfig({"bad": {"risk_score": 50, "severity": SEVERITY_HIGH, "category": "auth"}})


def test_metadata_is_masked():
    decision = AnomalyDetectionService().evaluate("unknown", metadata={"access_token": "abc123", "safe": "ok"})
    assert decision.metadata == {"access_token": "***", "safe": "ok"}


def test_alerting_requires_alert_feature_flag():
    cfg = AnomalyConfig({"x": {"risk_score": 70, "severity": SEVERITY_HIGH, "category": CATEGORY_REQUEST}})
    assert not AnomalyDetectionService(config=cfg, flags=DummyFlags()).evaluate("x").should_alert
    assert AnomalyDetectionService(config=cfg, flags=DummyFlags({ANOMALY_ALERTING_ENABLED: True})).evaluate("x").should_alert


def test_feature_flag_service_public_enabled_api_is_supported():
    from feature_flag_infra.interfaces import FeatureFlagProvider
    from feature_flag_infra.service import FeatureFlagService

    class Provider(FeatureFlagProvider):
        def is_enabled(self, flag, *, user=None, default=False):
            return {ANOMALY_ALERTING_ENABLED: True}.get(flag, default)

    cfg = AnomalyConfig({"x": {"risk_score": 70, "severity": SEVERITY_HIGH, "category": CATEGORY_REQUEST}})
    svc = AnomalyDetectionService(config=cfg, flags=FeatureFlagService(Provider()))

    assert svc.evaluate("x").should_alert


def test_blocking_requires_blocking_feature_flag():
    cfg = AnomalyConfig({"x": RuleProfile(100, SEVERITY_CRITICAL, CATEGORY_BUSINESS)})
    assert not AnomalyDetectionService(config=cfg, flags=DummyFlags()).evaluate("x").should_block
    assert AnomalyDetectionService(config=cfg, flags=DummyFlags({ANOMALY_BLOCKING_ENABLED: True})).evaluate("x").should_block


def test_step_up_activates_at_configured_threshold():
    cfg = AnomalyConfig({"x": RuleProfile(80, SEVERITY_CRITICAL, CATEGORY_BUSINESS)})
    decision = AnomalyDetectionService(config=cfg).evaluate("x")
    assert decision.should_step_up
    assert decision.action_taken == "step_up_review"


def test_record_returns_none_if_no_store_configured():
    svc = AnomalyDetectionService()
    decision = svc.evaluate("unknown")
    assert svc.record(decision, payload={"password": "secret"}) is None


def test_record_saves_event_when_store_exists_and_masks_payload():
    store = Store()
    svc = AnomalyDetectionService(event_store=store)
    decision = svc.evaluate("unknown")
    event = svc.record(decision, payload={"metadata": {"password": "secret"}, "masked_payload": {"api_key": "key"}})
    assert event.id == "event-1"
    assert store.saved[0]["metadata"]["password"] == "***"
    assert store.saved[0]["masked_payload"]["api_key"] == "***"


def test_record_dispatches_alert_only_when_should_alert_is_true():
    store = Store()
    dispatcher = Dispatcher()
    cfg = AnomalyConfig({"x": RuleProfile(70, SEVERITY_HIGH, CATEGORY_REQUEST)})
    svc = AnomalyDetectionService(event_store=store, alert_dispatcher=dispatcher, config=cfg, flags=DummyFlags())
    svc.record(svc.evaluate("x"), payload={"anomaly_type": "x"})
    assert dispatcher.dispatched == []

    svc = AnomalyDetectionService(
        event_store=store,
        alert_dispatcher=dispatcher,
        config=cfg,
        flags=DummyFlags({ANOMALY_ALERTING_ENABLED: True}),
    )
    svc.record(svc.evaluate("x"), payload={"anomaly_type": "x"})
    assert dispatcher.dispatched[-1][0] == "event-1"
