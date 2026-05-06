from __future__ import annotations

"""Framework-agnostic anomaly evaluation and recording service."""

import logging
from typing import Any, Protocol

from .config import AnomalyConfig
from .constants import (
    ALERT_THRESHOLD,
    ANOMALY_ALERTING_ENABLED,
    ANOMALY_BLOCKING_ENABLED,
    ANOMALY_DETECTION_ENABLED,
    BLOCK_THRESHOLD,
    STEP_UP_THRESHOLD,
)
from .defaults import DEFAULT_RULE_PROFILE
from .interfaces import AlertDispatcher, AnomalyEventStore
from .sanitizer import mask_sensitive
from .types import AnomalyDecision

logger = logging.getLogger(__name__)


class FeatureFlagClient(Protocol):
    """Subset of feature-flag-infra's public service API used by this package."""

    def enabled(self, flag: str, *, user: Any = None, default: bool = False) -> bool:
        ...


class StaticFeatureFlags:
    """Simple non-Django feature flag provider for manual use and tests."""

    def __init__(self, flags: dict[str, bool] | None = None):
        self.flags = flags or {}

    def enabled(self, flag: str, *, user: Any = None, default: bool = False) -> bool:
        return bool(self.flags.get(flag, default))

    def is_enabled(self, flag: str, *, user: Any = None, default: bool = False) -> bool:
        """Backward-compatible alias for provider-style flag clients."""
        return self.enabled(flag, user=user, default=default)


class AnomalyDetectionService:
    """Evaluate anomaly decisions and persist sanitized anomaly events."""

    def __init__(
        self,
        *,
        flags: FeatureFlagClient | None = None,
        event_store: AnomalyEventStore | None = None,
        alert_dispatcher: AlertDispatcher | None = None,
        config: AnomalyConfig | None = None,
    ):
        self.flags = flags or StaticFeatureFlags()
        self.event_store = event_store
        self.alert_dispatcher = alert_dispatcher
        self.config = config or AnomalyConfig()

    def is_enabled(self, *, user: Any = None) -> bool:
        return self.flag_enabled(ANOMALY_DETECTION_ENABLED, user=user, default=False)

    def flag_enabled(self, flag_name: str, *, user: Any = None, default: bool = False) -> bool:
        try:
            if hasattr(self.flags, "enabled"):
                return bool(self.flags.enabled(flag_name, user=user, default=default))
            return bool(self.flags.is_enabled(flag_name, user=user, default=default))
        except Exception:
            logger.exception("anomaly_feature_flag_check_failed", extra={"flag": flag_name})
            return bool(default)

    def evaluate(
        self,
        anomaly_type: str,
        *,
        metadata: dict | None = None,
        user: Any = None,
        user_message: str = "Suspicious activity detected.",
        internal_message: str = "",
    ) -> AnomalyDecision:
        profile = self.config.get_rule_profile(anomaly_type, DEFAULT_RULE_PROFILE)
        score = profile.risk_score

        should_alert = score >= ALERT_THRESHOLD and self.flag_enabled(
            ANOMALY_ALERTING_ENABLED, user=user, default=False
        )
        should_step_up = score >= STEP_UP_THRESHOLD
        should_block = score >= BLOCK_THRESHOLD and self.flag_enabled(
            ANOMALY_BLOCKING_ENABLED, user=user, default=False
        )

        action_taken = "block" if should_block else "alert" if should_alert else "step_up_review" if should_step_up else "log"

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

    def record(self, decision: AnomalyDecision, *, payload: dict | None = None) -> Any:
        """Persist a sanitized payload and optionally dispatch an alert."""
        if self.event_store is None:
            logger.info("anomaly_event_store_not_configured")
            return None

        sanitized_payload = mask_sensitive(payload or {})
        if "payload" in sanitized_payload:
            sanitized_payload.pop("payload", None)
        if "raw_payload" in sanitized_payload:
            sanitized_payload.pop("raw_payload", None)
        if "metadata" in sanitized_payload:
            sanitized_payload["metadata"] = mask_sensitive(sanitized_payload["metadata"] or {})
        if "masked_payload" in sanitized_payload:
            sanitized_payload["masked_payload"] = mask_sensitive(sanitized_payload["masked_payload"] or {})

        event = self.event_store.save(sanitized_payload)

        if decision.should_alert and self.alert_dispatcher:
            event_id = str(getattr(event, "id", ""))
            self.alert_dispatcher.dispatch(event_id, sanitized_payload)

        return event
