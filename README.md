# anomaly-infra

Reusable anomaly detection infrastructure for Django and Python applications.

`anomaly-infra` provides a small, framework-aware layer for evaluating suspicious activity, assigning risk metadata, sanitizing event payloads, persisting anomaly events, and optionally dispatching alerts. It is distributed as the `anomaly-infra` package and imported as `anomaly_infra`.

```bash
pip install anomaly-infra
```

The package is designed for two integration styles:

1. **Existing Django projects** that want middleware, ORM persistence, migrations, and Django settings-based configuration.
2. **Non-Django Python projects** that want the framework-agnostic anomaly evaluation service with custom event storage and alert dispatching.

This repository is a reusable library, **not** a standalone Django project. It intentionally does not include `manage.py`, URL routing, project settings, or application-specific business apps.

## What anomaly_infra solves

Most applications need a consistent way to detect and record suspicious behavior without coupling security logic to a single product domain. `anomaly_infra` centralizes that infrastructure by providing:

- A normalized anomaly decision object.
- Rule profiles that map anomaly types to risk scores, severities, and categories.
- Safe feature-flag-gated detection, alerting, blocking, and rule-level controls.
- Sanitized event persistence that avoids storing raw secrets.
- Django middleware for generic request/response anomaly patterns.
- A framework-agnostic service that can be used in any Python codebase.

The package does **not** provide domain-specific enforcement. Those checks should live in the consuming application and call `anomaly_infra` when suspicious behavior is observed.

## Key features

- Framework-agnostic `AnomalyDetectionService` for evaluating and recording anomalies.
- Django app integration via `anomaly_infra.django.apps.AnomalyInfraConfig`.
- Django middleware via `anomaly_infra.django.middleware.RequestAnomalyMiddleware`.
- Django ORM event model and packaged migration for `AnomalyEvent`.
- Integration with `feature-flag-infra` through its public Django service API.
- Configurable rule profiles with validation.
- Recursive sensitive-data masking for dictionaries, lists, tuples, and other non-string sequences.
- Safe defaults: detection, alerting, and blocking are disabled unless explicitly enabled by feature flags.
- Generic tenant/header mismatch detection without requiring a project-specific tenant model.
- Cache-backed counters for repeated failures, burst activity, and path probing.
- Optional transaction-isolated Django event persistence.

## Installation

```bash
pip install anomaly-infra
```

For local development from this repository:

```bash
pip install -e ".[dev]"
```

Optional extras declared by the package:

```bash
pip install "anomaly-infra[celery]"
pip install "anomaly-infra[redis]"
pip install "anomaly-infra[dev]"
```

The current implementation does not include Celery tasks or Redis-specific code paths; those extras are dependency conveniences for applications that use those tools around this package.

## Requirements

Runtime requirements from `pyproject.toml`:

- Python `>=3.9`
- Django `>=4.2`
- `feature-flag-infra>=0.1.0`

Although the core service is framework-agnostic, Django is currently a package dependency because this distribution includes Django models, middleware, providers, and migrations.

## Core concepts

### Anomaly decision

An anomaly decision is represented by `anomaly_infra.types.AnomalyDecision`. It is returned by `AnomalyDetectionService.evaluate(...)` and contains:

- `anomaly_type`
- `category`
- `severity`
- `risk_score`
- sanitized `metadata`
- `should_alert`
- `should_block`
- `should_step_up`
- `action_taken`
- `user_message`
- `internal_message`

### Rule profiles

A rule profile maps an anomaly type to a risk score, severity, and category. Profiles are represented by `anomaly_infra.types.RuleProfile` or by dictionaries with the same fields.

Package defaults are defined for common anomaly types such as:

- `invoice_amount_paid_tampering`
- `repeated_validation_failures`
- `repeated_forbidden_access`
- `cross_tenant_access_attempt`
- `burst_sensitive_endpoint_access`
- `path_probing`
- `invoice_total_mismatch`
- `invalid_invoice_status_transition`
- `stock_underflow_attempt`
- `duplicate_submission_pattern`

If an unknown anomaly type is evaluated, the service uses the default rule profile: risk score `30`, severity `medium`, category `request`.

### Risk score

`risk_score` is an integer from `0` to `100`.

The service uses the following built-in thresholds:

- `>= 50`: alert eligible when `ANOMALY_ALERTING_ENABLED` is enabled.
- `>= 80`: step-up review eligible.
- `>= 100`: blocking eligible when `ANOMALY_BLOCKING_ENABLED` is enabled.

### Severity

Supported severities are:

- `low`
- `medium`
- `high`
- `critical`

### Category

Supported categories are:

- `request`
- `permission`
- `business`

### Alerting

Alerting is controlled by `ANOMALY_ALERTING_ENABLED`. A decision only has `should_alert=True` when its risk score is at least `50` and the alerting flag is enabled.

In Django, the default `LoggingAlertDispatcher` writes a compact sanitized warning log containing only the event id, anomaly type, severity, and risk score.

### Blocking

Blocking is controlled by `ANOMALY_BLOCKING_ENABLED`. A decision only has `should_block=True` when its risk score is at least `100` and the blocking flag is enabled.

The core service returns the decision; it does not raise exceptions, return HTTP responses, or enforce business blocking by itself. Consuming applications should enforce blocking where appropriate.

### Step-up review

A decision has `should_step_up=True` when the risk score is at least `80`. Step-up review is represented in the returned decision so applications can require MFA, manual review, approval flows, or other application-specific verification.

## Feature flag integration

`anomaly-infra` depends on the published package [`feature-flag-infra`](https://pypi.org/project/feature-flag-infra/).

The Django service factory imports `feature_flag_infra.django.service.get_feature_flags()` lazily and passes that feature flag client into `AnomalyDetectionService`. The core service expects a feature flag client with an `enabled(flag, *, user=None, default=False)` method. It also supports an `is_enabled(...)` fallback for provider-style clients.

### Required and recommended feature flags

Create these flags in `feature-flag-infra` for normal operation:

| Flag | Purpose | Safe default used by `anomaly_infra` when missing |
| --- | --- | --- |
| `ANOMALY_DETECTION_ENABLED` | Global master switch for anomaly evaluation in Django middleware and service checks. | `False` |
| `ANOMALY_ALERTING_ENABLED` | Enables alert dispatch for decisions with risk score `>= 50`. | `False` |
| `ANOMALY_BLOCKING_ENABLED` | Enables blocking decisions for risk score `>= 100`. | `False` |
| `ANOMALY_RULE_BURST_ENABLED` | Enables middleware burst detection on sensitive endpoint prefixes. | `True` after global detection is enabled |
| `ANOMALY_RULE_PERMISSION_PROBING_ENABLED` | Enables repeated forbidden-access and path-probing middleware rules. | `True` after global detection is enabled |
| `ANOMALY_RULE_BUSINESS_TAMPERING_ENABLED` | Reserved feature flag constant for business-tampering rules called by application code. | Not currently used by Django middleware |
| `ANOMALY_RULE_CROSS_TENANT_ENABLED` | Enables middleware tenant-header mismatch detection. | `True` after global detection is enabled |

Recommended initial rollout:

1. Enable `ANOMALY_DETECTION_ENABLED` in a non-production or limited cohort.
2. Keep `ANOMALY_ALERTING_ENABLED=False` until event volume is understood.
3. Keep `ANOMALY_BLOCKING_ENABLED=False` until business enforcement paths are explicitly tested.
4. Enable or disable individual rule flags to tune middleware behavior.

## Django integration

### Minimal `INSTALLED_APPS` setup

Add both `feature-flag-infra` and `anomaly-infra` Django apps to your existing Django project:

```python
INSTALLED_APPS = [
    # Django apps...
    "django.contrib.auth",
    "django.contrib.contenttypes",

    # Feature flags must be installed for the default Django service factory.
    "feature_flag_infra.django.apps.FeatureFlagInfraConfig",

    # anomaly-infra Django integration.
    "anomaly_infra.django.apps.AnomalyInfraConfig",
]
```

Confirmed Django app config path:

```text
anomaly_infra.django.apps.AnomalyInfraConfig
```

Confirmed app label:

```text
anomaly_infra
```

### Middleware setup

Add the request anomaly middleware to `MIDDLEWARE`:

```python
MIDDLEWARE = [
    # ...your existing middleware...
    "anomaly_infra.django.middleware.RequestAnomalyMiddleware",
]
```

The middleware calls the downstream view first, then inspects the request and response. If `ANOMALY_DETECTION_ENABLED` is disabled, it returns the response without running any detectors.

### Migrations

`anomaly-infra` includes a packaged initial migration:

```text
anomaly_infra/django/migrations/0001_initial.py
```

Run migrations from your Django project:

```bash
python manage.py migrate
```

This creates the `AnomalyEvent` table for the app label `anomaly_infra`.

### Required feature flag setup

At minimum, create and enable the global detection flag in your feature flag system:

```text
ANOMALY_DETECTION_ENABLED=True
```

Then enable alerting and blocking only when you are ready:

```text
ANOMALY_ALERTING_ENABLED=True
ANOMALY_BLOCKING_ENABLED=False
```

The exact administration workflow depends on how your project uses `feature-flag-infra`.

### Settings configuration

A minimal safe configuration can be as small as:

```python
ANOMALY_TRUST_X_FORWARDED_FOR = False
```

A more complete configuration:

```python
ANOMALY_API_VERSION = "api/v1"
ANOMALY_TRUST_X_FORWARDED_FOR = False

ANOMALY_SENSITIVE_PREFIXES = (
    "/api/v1/auth/",
    "/api/v1/account/",
    "/api/v1/users/",
    "/api/v1/payments/",
)

ANOMALY_PROBE_PREFIXES = (
    "/admin/",
    "/api/v1/account/roles/",
    "/api/v1/users/",
)

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

### Usage in views or services

Use the Django service factory when you want to evaluate or record anomalies manually in a Django view, service, signal handler, or domain service:

```python
from anomaly_infra.django.request import build_event_payload
from anomaly_infra.django.service import get_anomaly_service


def my_view(request):
    anomaly_service = get_anomaly_service()

    decision = anomaly_service.evaluate(
        "duplicate_submission_pattern",
        user=getattr(request, "user", None),
        metadata={"form": "checkout"},
        user_message="We need to verify this request.",
    )

    if decision.should_step_up:
        # Start your application-specific verification flow.
        pass

    payload = build_event_payload(
        decision,
        request=request,
        user=getattr(request, "user", None),
        payload={"submitted_fields": ["shipping_address", "payment_method"]},
    )
    anomaly_service.record(decision, payload=payload)

    # Continue with your normal response handling.
```

### Usage in business logic

Business logic should evaluate application-specific anomalies directly. For example, if your application detects an invalid state transition:

```python
from anomaly_infra.django.service import get_anomaly_service


def validate_status_transition(*, user, current_status: str, requested_status: str) -> None:
    allowed = {("draft", "submitted"), ("submitted", "approved")}
    if (current_status, requested_status) in allowed:
        return

    anomaly_service = get_anomaly_service()
    decision = anomaly_service.evaluate(
        "invalid_invoice_status_transition",
        user=user,
        metadata={
            "current_status": current_status,
            "requested_status": requested_status,
        },
        user_message="Invalid status transition.",
    )
    anomaly_service.record(
        decision,
        payload={
            "anomaly_type": decision.anomaly_type,
            "category": decision.category,
            "severity": decision.severity,
            "risk_score": decision.risk_score,
            "user": user if getattr(user, "is_authenticated", False) else None,
            "metadata": decision.metadata,
            "action_taken": decision.action_taken,
            "blocked": decision.should_block,
        },
    )

    if decision.should_block:
        raise PermissionError(decision.user_message)
```

### How anomaly events are stored

The default Django service uses `DjangoAnomalyEventStore`, which creates `AnomalyEvent` rows through Django's ORM.

`AnomalyEvent` stores:

- anomaly type, category, severity, and risk score
- optional user foreign key
- generic tenant id/name fields
- request path, method, resource type, and resource id
- IP address, user agent, device id, and request id
- status code
- sanitized metadata and masked payload JSON
- action taken and blocked flag
- resolution fields (`resolved`, `resolved_at`, `notes`)
- timestamps

By default, `DjangoAnomalyEventStore` attempts to persist events outside an active business transaction by using an autocommit clone of the configured database connection. This behavior is controlled by settings documented below.

## Django settings reference

Only the following Django settings are read by the current codebase.

| Setting | Default | Used by | Description |
| --- | --- | --- | --- |
| `ANOMALY_RULE_PROFILES` | `{}` | Django service factory | Project overrides or additions for rule profiles. Merged with package defaults. |
| `ANOMALY_API_VERSION` | `"api/v1"` | Middleware | API version used to construct default sensitive and probe prefixes. Leading/trailing slashes are normalized. |
| `ANOMALY_SENSITIVE_PREFIXES` | `("/api/v1/auth/", "/api/v1/account/", "/api/v1/users/", "/api/v1/invoice/", "/api/v1/payments/")` | Middleware | Path prefixes considered sensitive for burst detection. |
| `ANOMALY_PROBE_PREFIXES` | `("/admin/", "/api/v1/account/roles/", "/api/v1/users/")` | Middleware | Path prefixes considered probe-prone for path probing detection. |
| `ANOMALY_BURST_THRESHOLD` | `20` | Middleware | Number of write requests to a sensitive prefix before recording `burst_sensitive_endpoint_access`. |
| `ANOMALY_BURST_WINDOW_SECONDS` | `60` | Middleware | Cache TTL/window for burst counters. |
| `ANOMALY_VALIDATION_FAILURE_THRESHOLD` | `5` | Middleware | Number of `400` or `403` responses by actor before recording repeated failure anomalies. |
| `ANOMALY_VALIDATION_FAILURE_WINDOW_SECONDS` | `120` | Middleware | Cache TTL/window for repeated validation/forbidden counters. |
| `ANOMALY_PATH_PROBE_THRESHOLD` | `10` | Middleware | Number of requests to the same probe path by actor before recording `path_probing`. |
| `ANOMALY_PATH_PROBE_WINDOW_SECONDS` | `300` | Middleware | Cache TTL/window for path probe counters. |
| `ANOMALY_TRUST_X_FORWARDED_FOR` | `False` | Request helpers | When `True`, `get_ip()` uses the first value in `X-Forwarded-For`; otherwise it uses `REMOTE_ADDR`. |
| `ANOMALY_PERSIST_EVENTS_OUTSIDE_TRANSACTIONS` | `True` | Django event store | When enabled, event persistence inside `transaction.atomic()` uses an independent autocommit database alias where possible. |
| `ANOMALY_EVENT_DATABASE_ALIAS` | `None` | Django event store | Optional explicit database alias for transaction-independent anomaly event writes. |

## Rule profile configuration

### Default rule profile behavior

`AnomalyConfig` always starts with package defaults and then applies overrides supplied by the application.

```python
from anomaly_infra.config import AnomalyConfig

config = AnomalyConfig()
profile = config.get_rule_profile("cross_tenant_access_attempt", default=None)
```

If `evaluate()` receives an anomaly type not present in `config.rule_profiles`, the service uses the package default fallback profile:

```python
risk_score = 30
severity = "medium"
category = "request"
```

### Override profiles in Django `settings.py`

```python
ANOMALY_RULE_PROFILES = {
    "cross_tenant_access_attempt": {
        "risk_score": 75,
        "severity": "high",
        "category": "permission",
    },
    "custom_checkout_velocity": {
        "risk_score": 65,
        "severity": "high",
        "category": "business",
    },
}
```

The Django service factory reads these settings when `get_anomaly_service()` first creates its cached singleton. In tests or dynamic configuration scenarios, call `anomaly_infra.django.service.reset_anomaly_service()` to clear the cached service.

### Configure profiles in non-Django Python

```python
from anomaly_infra.config import AnomalyConfig
from anomaly_infra.service import AnomalyDetectionService, StaticFeatureFlags

config = AnomalyConfig(
    rule_profiles={
        "custom_rule": {
            "risk_score": 55,
            "severity": "high",
            "category": "request",
        },
    }
)

service = AnomalyDetectionService(
    flags=StaticFeatureFlags({"ANOMALY_DETECTION_ENABLED": True}),
    config=config,
)
```

### Validation rules

Invalid rule profile configuration raises immediately during `AnomalyConfig(...)` construction.

- `risk_score` must be an `int` from `0` through `100`.
- `severity` must be one of `low`, `medium`, `high`, or `critical`.
- `category` must be one of `request`, `permission`, or `business`.
- Profile names must be non-empty strings.
- Each dictionary profile must include `risk_score`, `severity`, and `category`.

## Non-Django Python usage

The framework-agnostic API lives under `anomaly_infra.config`, `anomaly_infra.service`, `anomaly_infra.interfaces`, and `anomaly_infra.types`.

### `AnomalyDetectionService`

`AnomalyDetectionService` evaluates anomaly types against configured rule profiles and records sanitized events through an optional event store.

Important methods:

- `is_enabled(user=None) -> bool`
- `flag_enabled(flag_name, user=None, default=False) -> bool`
- `evaluate(anomaly_type, metadata=None, user=None, user_message="...", internal_message="...") -> AnomalyDecision`
- `record(decision, payload=None) -> Any`

### Custom `AnomalyEventStore`

Implement `anomaly_infra.interfaces.AnomalyEventStore` or provide any object with a compatible `save(payload: dict)` method. The service passes a sanitized payload to `save()`.

### Custom `AlertDispatcher`

Implement `anomaly_infra.interfaces.AlertDispatcher` or provide any object with a compatible `dispatch(event_id: str, payload: dict | None = None)` method. The dispatcher is called only when `decision.should_alert` is `True`.

### `FeatureFlagService` usage

For non-Django applications, pass a feature flag client that supports:

```python
enabled(flag: str, *, user=None, default: bool = False) -> bool
```

This can be a client from `feature-flag-infra`, a wrapper around your own flag system, or `StaticFeatureFlags` for simple setups and tests.

### Complete copy-paste example

```python
from dataclasses import dataclass

from anomaly_infra.config import AnomalyConfig
from anomaly_infra.constants import (
    ANOMALY_ALERTING_ENABLED,
    ANOMALY_DETECTION_ENABLED,
)
from anomaly_infra.service import AnomalyDetectionService, StaticFeatureFlags


@dataclass
class StoredEvent:
    id: str
    payload: dict


class InMemoryAnomalyEventStore:
    def __init__(self):
        self.events = []

    def save(self, payload: dict):
        event = StoredEvent(id=f"event-{len(self.events) + 1}", payload=payload)
        self.events.append(event)
        return event


class PrintAlertDispatcher:
    def dispatch(self, event_id: str, payload: dict | None = None):
        print(f"alert dispatched for {event_id}: {payload.get('anomaly_type')}")


flags = StaticFeatureFlags(
    {
        ANOMALY_DETECTION_ENABLED: True,
        ANOMALY_ALERTING_ENABLED: True,
    }
)
store = InMemoryAnomalyEventStore()

service = AnomalyDetectionService(
    flags=flags,
    event_store=store,
    alert_dispatcher=PrintAlertDispatcher(),
    config=AnomalyConfig(
        rule_profiles={
            "custom_login_velocity": {
                "risk_score": 60,
                "severity": "high",
                "category": "request",
            },
        }
    ),
)

if service.is_enabled():
    decision = service.evaluate(
        "custom_login_velocity",
        metadata={
            "username": "sam@example.com",
            "access_token": "secret-token-that-will-be-masked",
            "attempt_count": 8,
        },
        user_message="Additional verification is required.",
    )

    event = service.record(
        decision,
        payload={
            "anomaly_type": decision.anomaly_type,
            "category": decision.category,
            "severity": decision.severity,
            "risk_score": decision.risk_score,
            "metadata": decision.metadata,
            "masked_payload": {
                "password": "raw secret will be masked",
                "safe_field": "safe value",
            },
            "action_taken": decision.action_taken,
            "blocked": decision.should_block,
        },
    )

    print(event.id)
    print(event.payload)
```

## Manual anomaly recording example

Manual recording is appropriate when application code detects a domain-specific condition that middleware cannot know about.

```python
from anomaly_infra.constants import ANOMALY_DETECTION_ENABLED
from anomaly_infra.service import AnomalyDetectionService, StaticFeatureFlags

service = AnomalyDetectionService(
    flags=StaticFeatureFlags({ANOMALY_DETECTION_ENABLED: True}),
)

decision = service.evaluate(
    "stock_underflow_attempt",
    metadata={"sku": "SKU-001", "requested_quantity": 25, "available_quantity": 3},
    user_message="Requested quantity is not available.",
)

if decision.should_block:
    # Enforce your application-specific block here.
    pass

# Without an event_store, record() logs that no store is configured and returns None.
service.record(decision, payload={"metadata": decision.metadata})
```

In production, pass an event store so `record()` can persist the sanitized event.

## Middleware behavior

`RequestAnomalyMiddleware` is intentionally generic and framework-isolated. It does not import project-specific apps and does not require a tenant model.

The middleware detects the following patterns after the response is produced:

1. **Tenant header mismatch**
   - Rule: `cross_tenant_access_attempt`
   - Controlled by: `ANOMALY_RULE_CROSS_TENANT_ENABLED`
   - Compares `X-Tenant` or `X-Tenant-Id` headers with `request.tenant.id`, `request.tenant.name`, or `request.tenant_id` when available.

2. **Repeated validation failures**
   - Rule: `repeated_validation_failures`
   - Triggered by repeated `400` responses from the same actor.
   - Threshold/window: `ANOMALY_VALIDATION_FAILURE_THRESHOLD` and `ANOMALY_VALIDATION_FAILURE_WINDOW_SECONDS`.

3. **Repeated forbidden access**
   - Rule: `repeated_forbidden_access`
   - Controlled by: `ANOMALY_RULE_PERMISSION_PROBING_ENABLED`
   - Triggered by repeated `403` responses from the same actor.
   - Threshold/window: `ANOMALY_VALIDATION_FAILURE_THRESHOLD` and `ANOMALY_VALIDATION_FAILURE_WINDOW_SECONDS`.

4. **Burst sensitive endpoint access**
   - Rule: `burst_sensitive_endpoint_access`
   - Controlled by: `ANOMALY_RULE_BURST_ENABLED`
   - Applies to `POST`, `PUT`, `PATCH`, and `DELETE` requests whose path starts with one of `ANOMALY_SENSITIVE_PREFIXES`.
   - Threshold/window: `ANOMALY_BURST_THRESHOLD` and `ANOMALY_BURST_WINDOW_SECONDS`.

5. **Path probing**
   - Rule: `path_probing`
   - Controlled by: `ANOMALY_RULE_PERMISSION_PROBING_ENABLED`
   - Applies to paths that start with one of `ANOMALY_PROBE_PREFIXES`.
   - Threshold/window: `ANOMALY_PATH_PROBE_THRESHOLD` and `ANOMALY_PATH_PROBE_WINDOW_SECONDS`.

Actor counters use the authenticated `user.id` when available; otherwise they use the detected IP address or `anon`.

The global detection flag disables all middleware detectors:

```text
ANOMALY_DETECTION_ENABLED=False
```

When the global flag is disabled or missing, middleware returns the response without recording events.

## Security model

### Sensitive data masking

`mask_sensitive()` recursively masks values for keys that contain sensitive fragments. Matching is case-insensitive and normalizes hyphens to underscores.

Sensitive fragments include:

```text
password, token, refresh, access, authorization, secret, api_key,
card, cvv, pin, cookie, session, csrf, set-cookie
```

Masked values are replaced with:

```text
***
```

### No raw secret persistence

`AnomalyDetectionService.record()` sanitizes payloads before saving. It removes top-level `payload` and `raw_payload` keys and re-sanitizes `metadata` and `masked_payload` when present.

The Django request payload builder stores sanitized `metadata` and `masked_payload`; it does not persist raw request bodies.

### `X-Forwarded-For` trust setting

By default, `ANOMALY_TRUST_X_FORWARDED_FOR=False`, so IP extraction uses `REMOTE_ADDR`.

Set this to `True` only if your application is behind a trusted proxy that correctly sets and sanitizes `X-Forwarded-For`:

```python
ANOMALY_TRUST_X_FORWARDED_FOR = True
```

### Framework isolation

The core service has no Django dependency in its import path. Django-specific code lives under `anomaly_infra.django`.

The Django middleware is generic and avoids imports from consuming project apps.

### Safe defaults

- Global anomaly detection defaults to disabled.
- Alerting defaults to disabled.
- Blocking defaults to disabled.
- Rule-level middleware flags default to enabled only after global detection is enabled.
- Payloads are sanitized before event persistence and alert logging.
- Forwarded IP headers are ignored unless explicitly trusted.

## Testing

Install development dependencies, then run:

```bash
pytest
```

The repository also supports the pytest configuration in `pytest.ini`, which sets `DJANGO_SETTINGS_MODULE=tests.settings` and uses pytest-django.

Current test coverage areas include:

- Rule profile defaults, overrides, and validation.
- Decision thresholds for alerting, blocking, and step-up review.
- Feature flag behavior and safe fallbacks.
- Payload and metadata sanitization.
- Django app configuration and migrations.
- Django model persistence and `mark_resolved()` behavior.
- Request IP extraction and `X-Forwarded-For` trust behavior.
- Middleware detection for disabled global detection, repeated `400`/`403` responses, sensitive endpoint bursts, tenant mismatch, path probing, anonymous users, and non-standard responses.
- Transaction-independent Django event persistence.

Useful packaging commands from the `Makefile`:

```bash
make clean
make build
```

## Package structure

```text
anomaly_infra/
  __init__.py
  config.py                  # AnomalyConfig and rule profile validation
  constants.py               # Feature flag names, categories, severities, thresholds
  defaults.py                # Bundled default rule profiles
  interfaces.py              # AnomalyEventStore and AlertDispatcher interfaces
  sanitizer.py               # Recursive sensitive-data masking
  service.py                 # Framework-agnostic AnomalyDetectionService
  types.py                   # RuleProfile and AnomalyDecision dataclasses
  django/
    __init__.py
    apps.py                  # AnomalyInfraConfig; app label anomaly_infra
    counters.py              # Cache-backed counter helpers
    middleware.py            # RequestAnomalyMiddleware
    migrations/
      0001_initial.py        # AnomalyEvent migration
    models.py                # AnomalyEvent ORM model
    providers.py             # DjangoAnomalyEventStore and LoggingAlertDispatcher
    request.py               # Request metadata/IP/payload helpers
    service.py               # get_anomaly_service() factory

tests/
  conftest.py
  settings.py
  test_core.py
  test_debug_settings.py
  test_django_integration.py
  test_sanitizer.py
```

## Public APIs documented

Core APIs:

- `anomaly_infra.config.AnomalyConfig`
- `anomaly_infra.service.AnomalyDetectionService`
- `anomaly_infra.service.StaticFeatureFlags`
- `anomaly_infra.interfaces.AnomalyEventStore`
- `anomaly_infra.interfaces.AlertDispatcher`
- `anomaly_infra.types.RuleProfile`
- `anomaly_infra.types.AnomalyDecision`
- `anomaly_infra.sanitizer.mask_sensitive`

Django APIs:

- `anomaly_infra.django.apps.AnomalyInfraConfig`
- `anomaly_infra.django.middleware.RequestAnomalyMiddleware`
- `anomaly_infra.django.models.AnomalyEvent`
- `anomaly_infra.django.providers.DjangoAnomalyEventStore`
- `anomaly_infra.django.providers.LoggingAlertDispatcher`
- `anomaly_infra.django.request.get_ip`
- `anomaly_infra.django.request.get_user_agent`
- `anomaly_infra.django.request.request_meta`
- `anomaly_infra.django.request.build_event_payload`
- `anomaly_infra.django.service.get_anomaly_service`
- `anomaly_infra.django.service.reset_anomaly_service`

## Roadmap

The following items are not implemented in the current codebase but are natural future extensions:

- First-class documentation examples for specific `feature-flag-infra` admin workflows.
- Pluggable alert dispatchers for email, Slack, webhooks, or task queues.
- Optional Celery task helpers for asynchronous alert delivery.
- Optional Redis-specific counter backend guidance and operational tuning.
- Management commands for anomaly event cleanup, export, or reporting.
- Admin UI helpers for reviewing and resolving anomaly events.
- Additional framework integrations beyond Django.
- More built-in rule profiles and detector helpers driven by real-world application patterns.

## License

MIT License. See [`LICENSE`](LICENSE).
