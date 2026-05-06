from __future__ import annotations

"""Framework-agnostic configuration for anomaly-infra."""

from collections.abc import Mapping
from typing import Any

from .constants import VALID_CATEGORIES, VALID_SEVERITIES
from .defaults import DEFAULT_RULE_PROFILES
from .types import RuleProfile


class AnomalyConfig:
    """Validated anomaly configuration.

    ``rule_profiles`` may override or add package defaults. Each profile must be a
    :class:`RuleProfile` or a dict with ``risk_score``, ``severity`` and
    ``category``.
    """

    def __init__(self, rule_profiles: Mapping[str, RuleProfile | Mapping[str, Any]] | None = None):
        self.rule_profiles = {
            **DEFAULT_RULE_PROFILES,
            **self._normalize_profiles(rule_profiles or {}),
        }

    def get_rule_profile(self, anomaly_type: str, default: RuleProfile) -> RuleProfile:
        return self.rule_profiles.get(anomaly_type, default)

    def _normalize_profiles(self, profiles: Mapping[str, RuleProfile | Mapping[str, Any]]) -> dict[str, RuleProfile]:
        if not isinstance(profiles, Mapping):
            raise TypeError("rule_profiles must be a mapping of anomaly type to profile")

        normalized: dict[str, RuleProfile] = {}
        for name, value in profiles.items():
            if not isinstance(name, str) or not name:
                raise TypeError("rule profile names must be non-empty strings")

            if isinstance(value, RuleProfile):
                profile = value
            elif isinstance(value, Mapping):
                missing = {"risk_score", "severity", "category"} - set(value)
                if missing:
                    raise ValueError(f"Rule profile {name!r} is missing fields: {sorted(missing)}")
                profile = RuleProfile(
                    risk_score=value["risk_score"],
                    severity=value["severity"],
                    category=value["category"],
                )
            else:
                raise TypeError(f"Invalid rule profile for {name!r}. Expected RuleProfile or dict.")

            self._validate_profile(name, profile)
            normalized[name] = profile
        return normalized

    @staticmethod
    def _validate_profile(name: str, profile: RuleProfile) -> None:
        if type(profile.risk_score) is not int:
            raise TypeError(f"Rule profile {name!r} risk_score must be an int")
        if not 0 <= profile.risk_score <= 100:
            raise ValueError(f"Rule profile {name!r} risk_score must be between 0 and 100")
        if profile.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Rule profile {name!r} severity must be one of {sorted(VALID_SEVERITIES)}"
            )
        if profile.category not in VALID_CATEGORIES:
            raise ValueError(
                f"Rule profile {name!r} category must be one of {sorted(VALID_CATEGORIES)}"
            )
