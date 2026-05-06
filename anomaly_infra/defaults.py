"""Default anomaly rule profiles bundled with the package."""

from .constants import (
    CATEGORY_BUSINESS,
    CATEGORY_PERMISSION,
    CATEGORY_REQUEST,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from .types import RuleProfile

DEFAULT_RULE_PROFILE = RuleProfile(30, SEVERITY_MEDIUM, CATEGORY_REQUEST)

DEFAULT_RULE_PROFILES = {
    "invoice_amount_paid_tampering": RuleProfile(90, SEVERITY_CRITICAL, CATEGORY_BUSINESS),
    "repeated_validation_failures": RuleProfile(10, SEVERITY_LOW, CATEGORY_REQUEST),
    "repeated_forbidden_access": RuleProfile(20, SEVERITY_MEDIUM, CATEGORY_PERMISSION),
    "cross_tenant_access_attempt": RuleProfile(50, SEVERITY_HIGH, CATEGORY_PERMISSION),
    "burst_sensitive_endpoint_access": RuleProfile(60, SEVERITY_HIGH, CATEGORY_REQUEST),
    "path_probing": RuleProfile(60, SEVERITY_HIGH, CATEGORY_PERMISSION),
    "invoice_total_mismatch": RuleProfile(70, SEVERITY_HIGH, CATEGORY_BUSINESS),
    "invalid_invoice_status_transition": RuleProfile(80, SEVERITY_CRITICAL, CATEGORY_BUSINESS),
    "stock_underflow_attempt": RuleProfile(75, SEVERITY_HIGH, CATEGORY_BUSINESS),
    "duplicate_submission_pattern": RuleProfile(45, SEVERITY_MEDIUM, CATEGORY_REQUEST),
}
