from .defaults import DEFAULT_RULE_PROFILES
from .types import RuleProfile


class AnomalyConfig:
    def __init__(self, rule_profiles=None):
        self.rule_profiles = {
            **DEFAULT_RULE_PROFILES,
            **self._normalize_profiles(rule_profiles or {}),
        }

    def get_rule_profile(self, anomaly_type: str, default: RuleProfile) -> RuleProfile:
        return self.rule_profiles.get(anomaly_type, default)

    def _normalize_profiles(self, profiles: dict) -> dict[str, RuleProfile]:
        normalized = {}

        for name, value in profiles.items():
            if isinstance(value, RuleProfile):
                normalized[name] = value
                continue

            if isinstance(value, dict):
                normalized[name] = RuleProfile(
                    risk_score=value["risk_score"],
                    severity=value["severity"],
                    category=value["category"],
                )
                continue

            raise TypeError(
                f"Invalid rule profile for {name}. "
                "Expected RuleProfile or dict."
            )

        return normalized