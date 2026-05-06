# anomaly-infra

Reusable anomaly detection infrastructure for Django and non-Django Python projects.

* Install package name: `anomaly-infra`
* Python import name: `anomaly_infra`
* Feature flag integration: [`feature-flag-infra`](https://pypi.org/project/feature-flag-infra/) public APIs only

The core package is framework-agnostic. Django-specific models, providers, request helpers, counters, middleware, and service factory live under `anomaly_infra.django`.

## Security defaults

`anomaly-infra` is intentionally conservative:

* Global detection defaults to **disabled** when `ANOMALY_DETECTION_ENABLED` is missing.
* Alerting and blocking default to **disabled** unless their flags are enabled.
* Individual rule flags default to enabled only after global detection is enabled.
* Request payloads are recursively masked before persistence/logging.
* Raw payloads are not persisted by the service.
* `X-Forwarded-For` is ignored unless `ANOMALY_TRUST_X_FORWARDED_FOR = True`.
* Middleware is generic and does not depend on project apps such as tenant, account, invoice, RBAC, or alert apps.

Sensitive key matching is case-insensitive and substring-based. Examples include `password`, `access_token`, `refresh_token`, `authorization`, `secret`, `api_key`, `card`, `cvv`, `pin`, `cookie`, `session`, `csrfmiddlewaretoken`, and `set-cookie`.

## Feature flags

The following feature flags are used through `feature_flag_infra`:

```text
ANOMALY_DETECTION_ENABLED
ANOMALY_ALERTING_ENABLED
ANOMALY_BLOCKING_ENABLED
ANOMALY_RULE_BURST_ENABLED
ANOMALY_RULE_PERMISSION_PROBING_ENABLED
ANOMALY_RULE_BUSINESS_TAMPERING_ENABLED
ANOMALY_RULE_CROSS_TENANT_ENABLED
```

If a flag is missing, `feature-flag-infra` receives a safe default (`False` for global detection, alerting, and blocking).

## Django usage

Install and add the app:

```python
INSTALLED_APPS = [
    # ...
    "feature_flag_infra.django.apps.FeatureFlagInfraConfig",
    "anomaly_infra.django.apps.AnomalyInfraConfig",
]

MIDDLEWARE = [
    # ...
    "anomaly_infra.django.middleware.RequestAnomalyMiddleware",
]
```

Run migrations:

```bash
python manage.py migrate
```

Optional settings:

```python
ANOMALY_TRUST_X_FORWARDED_FOR = False
ANOMALY_API_VERSION = "api/v1"
ANOMALY_SENSITIVE_PREFIXES = ("/api/v1/account/", "/api/v1/payments/")
ANOMALY_PROBE_PREFIXES = ("/admin/", "/api/v1/account/roles/")
ANOMALY_BURST_THRESHOLD = 20
ANOMALY_BURST_WINDOW_SECONDS = 60
ANOMALY_VALIDATION_FAILURE_THRESHOLD = 5
ANOMALY_VALIDATION_FAILURE_WINDOW_SECONDS = 120
ANOMALY_PATH_PROBE_THRESHOLD = 10
ANOMALY_PATH_PROBE_WINDOW_SECONDS = 300

ANOMALY_RULE_PROFILES = {
    "cross_tenant_access_attempt": {
        "risk_score": 70,
        "severity": "high",
        "category": "permission",
    },
}
```

Django service helper:

```python
from anomaly_infra.django.service import get_anomaly_service

service = get_anomaly_service()
decision = service.evaluate("cross_tenant_access_attempt", metadata={"tenant_id": "other"})
```

The helper lazily imports Django providers/models and obtains flags via `feature_flag_infra.django.service.get_feature_flags`.

## Non-Django usage

Provide your own feature flag provider, event store, and alert dispatcher:

```python
from anomaly_infra.config import AnomalyConfig
from anomaly_infra.service import AnomalyDetectionService, StaticFeatureFlags

class EventStore:
    def save(self, payload: dict):
        # Persist only the sanitized payload you receive here.
        return {"id": "event-1", **payload}

class AlertDispatcher:
    def dispatch(self, event_id: str, payload: dict | None = None):
        print("alert", event_id)

service = AnomalyDetectionService(
    flags=StaticFeatureFlags({
        "ANOMALY_DETECTION_ENABLED": True,
        "ANOMALY_ALERTING_ENABLED": True,
    }),
    event_store=EventStore(),
    alert_dispatcher=AlertDispatcher(),
    config=AnomalyConfig(rule_profiles={
        "custom_rule": {"risk_score": 55, "severity": "high", "category": "request"},
    }),
)

if service.is_enabled():
    decision = service.evaluate("custom_rule", metadata={"access_token": "secret"})
    service.record(decision, payload={
        "anomaly_type": decision.anomaly_type,
        "metadata": decision.metadata,
        "masked_payload": {"password": "secret"},
    })
```

## Rule profile validation

Rule profiles are merged from package defaults plus overrides. Invalid overrides raise `TypeError` or `ValueError` immediately.

Required profile fields:

* `risk_score`: `int` from `0` through `100`
* `severity`: one of `low`, `medium`, `high`, `critical`
* `category`: one of `request`, `permission`, `business`

## Django model

`AnomalyEvent` uses generic tenant/resource fields and does not require a Tenant model:

* `tenant_id`, `tenant_name`
* `resource_type`, `resource_id`
* `metadata`, `masked_payload`
* `action_taken`, `blocked`, `resolved`, `resolved_at`, `notes`

Indexes are included for common triage queries: `category + severity`, `tenant_id + created_at`, `anomaly_type + created_at`, `resolved + created_at`, and `action_taken + created_at`.

### Transaction rollback behavior

`DjangoAnomalyEventStore` records through a separate autocommit database connection whenever it is called inside a `transaction.atomic()` block. This keeps anomaly audit rows available even if the surrounding business transaction rolls back.

Optional Django settings:

* `ANOMALY_PERSIST_EVENTS_OUTSIDE_TRANSACTIONS` (default: `True`) disables or enables the separate-connection behavior.
* `ANOMALY_EVENT_DATABASE_ALIAS` can point anomaly writes at an explicit database alias. If omitted, the store clones the active database alias into an autocommit alias that uses the same database configuration.

In-memory SQLite databases cannot share schema and rows with a cloned connection, so the store safely falls back to the current connection in that environment. Use a file-backed SQLite database, PostgreSQL, MySQL, or an explicit `ANOMALY_EVENT_DATABASE_ALIAS` when you need rollback-resistant anomaly records.
