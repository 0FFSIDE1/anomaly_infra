from dataclasses import dataclass, field


@dataclass(frozen=True)
class RuleProfile:
    risk_score: int
    severity: str
    category: str


@dataclass
class AnomalyDecision:
    anomaly_type: str
    category: str
    severity: str
    risk_score: int
    metadata: dict = field(default_factory=dict)
    should_alert: bool = False
    should_block: bool = False
    should_step_up: bool = False
    action_taken: str = "log"
    user_message: str = "Suspicious activity detected."
    internal_message: str = ""