import logging
from typing import Any

from feature_flag_infra.django.service import get_feature_flags

from .constants import (
    ALERT_THRESHOLD,
    ANOMALY_ALERTING_ENABLED,
    ANOMALY_BLOCKING_ENABLED,
    ANOMALY_DETECTION_ENABLED,
    BLOCK_THRESHOLD,
    DEFAULT_RULE_PROFILE,
    RULE_PROFILES,
    STEP_UP_THRESHOLD,
)
from .interfaces import AlertDispatcher, AnomalyEventStore
from .sanitizer import mask_sensitive
from .types import AnomalyDecision

logger = logging.getLogger(__name__)

FeatureFlagService = get_feature_flags()

class AnomalyDetectionService:
    def __init__(
        self,
        *,
        flags: FeatureFlagService,
        event_store: AnomalyEventStore | None = None,
        alert_dispatcher: AlertDispatcher | None = None,
        config: AnomalyConfig | None = None,
    ):
        self.flags = flags
        self.event_store = event_store
        self.alert_dispatcher = alert_dispatcher
        self.config = config or AnomalyConfig()

    def is_enabled(self, *, user: Any = None) -> bool:
        return self.flags.enabled(
            ANOMALY_DETECTION_ENABLED,
            user=user,
            default=False,
        )

    def flag_enabled(self, flag_name: str, *, user: Any = None, default=False) -> bool:
        return self.flags.enabled(
            flag_name,
            user=user,
            default=default,
        )

    def evaluate(
        self,
        anomaly_type: str,
        *,
        metadata: dict | None = None,
        user: Any = None,
        user_message: str = "Suspicious activity detected.",
        internal_message: str = "",
    ) -> AnomalyDecision:
        profile = self.config.get_rule_profile(
            anomaly_type,
            DEFAULT_RULE_PROFILE,
        )

        score = profile.risk_score

        should_alert = (
            score >= ALERT_THRESHOLD
            and self.flag_enabled(ANOMALY_ALERTING_ENABLED, user=user, default=False)
        )

        should_step_up = score >= STEP_UP_THRESHOLD

        should_block = (
            score >= BLOCK_THRESHOLD
            and self.flag_enabled(ANOMALY_BLOCKING_ENABLED, user=user, default=False)
        )

        action_taken = "log"

        if should_block:
            action_taken = "block"
        elif should_alert:
            action_taken = "alert"
        elif should_step_up:
            action_taken = "step_up_review"

        return AnomalyDecision(
            anomaly_type=anomaly_type,
            category=profile.category,
            severity=profile.severity,
            risk_score=score,
            metadata=mask_sensitive(metadata or {}),
            should_alert=should_alert,
            should_block=should_block,
            should_step_up=should_step_up,
            action_taken=action_taken,
            user_message=user_message,
            internal_message=internal_message,
        )

    def record(self, decision: AnomalyDecision, *, payload: dict) -> Any:
        if self.event_store is None:
            logger.warning("anomaly_event_store_not_configured")
            return None

        event = self.event_store.save(payload)

        if decision.should_alert and self.alert_dispatcher:
            event_id = str(getattr(event, "id", ""))
            self.alert_dispatcher.dispatch(event_id, payload)

        return event