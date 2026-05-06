import re

from django.conf import settings

from anomaly_infra.constants import (
    ANOMALY_RULE_BURST_ENABLED,
    ANOMALY_RULE_CROSS_TENANT_ENABLED,
    ANOMALY_RULE_PERMISSION_PROBING_ENABLED,
)
from anomaly_infra.django.counters import increment_counter, key
from anomaly_infra.django.request import build_event_payload
from anomaly_infra.django.service import get_anomaly_service


class RequestAnomalyMiddleware:
    RESOURCE_ID_PATTERN = re.compile(
        r"^\d+$|^[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}$"
    )

    def __init__(self, get_response):
        self.get_response = get_response

        version = getattr(settings, "ANOMALY_API_VERSION", "api/v1")

        self.sensitive_prefixes = getattr(
            settings,
            "ANOMALY_SENSITIVE_PREFIXES",
            (
                f"/{version}/account/login",
                f"/{version}/account/refresh",
                f"/{version}/invoice/",
            ),
        )

        self.probe_prefixes = getattr(
            settings,
            "ANOMALY_PROBE_PREFIXES",
            (
                "/admin/",
                f"/{version}/account/roles/",
            ),
        )

    def __call__(self, request):
        response = self.get_response(request)

        user = getattr(request, "user", None)
        anomaly_service = get_anomaly_service()

        if not anomaly_service.is_enabled(user=user):
            return response

        self._detect_tenant_header_mismatch(request, user, anomaly_service)
        self._detect_response_pattern(request, response, user, anomaly_service)
        self._detect_burst(request, user, anomaly_service)
        self._detect_path_probing(request, user, anomaly_service)

        return response

    def _record(self, request, user, anomaly_service, decision, *, status_code=None):
        resource_type, resource_id = self._extract_resource(request.path)
        request.anomaly_resource_id = resource_id

        payload = build_event_payload(
            decision,
            request=request,
            user=user,
            tenant=getattr(request, "tenant", None),
            status_code=status_code,
            resource_type=resource_type,
            resource_id=resource_id,
        )

        anomaly_service.record(decision, payload=payload)

    def _detect_tenant_header_mismatch(self, request, user, anomaly_service):
        if not anomaly_service.flag_enabled(
            ANOMALY_RULE_CROSS_TENANT_ENABLED,
            user=user,
            default=True,
        ):
            return

        header_tenant = request.META.get("HTTP_X_TENANT")
        request_tenant = getattr(
            getattr(request, "tenant", None),
            "name",
            getattr(request, "tenant", None),
        )

        if header_tenant and request_tenant and header_tenant != request_tenant:
            decision = anomaly_service.evaluate(
                "cross_tenant_access_attempt",
                user=user,
                metadata={
                    "header_tenant": header_tenant,
                    "request_tenant": request_tenant,
                },
                user_message="Invalid request.",
            )

            self._record(
                request,
                user,
                anomaly_service,
                decision,
                status_code=400,
            )

    def _detect_response_pattern(self, request, response, user, anomaly_service):
        if response.status_code not in {400, 403}:
            return

        if response.status_code == 403 and not anomaly_service.flag_enabled(
            ANOMALY_RULE_PERMISSION_PROBING_ENABLED,
            user=user,
            default=True,
        ):
            return

        label = (
            "repeated_validation_failures"
            if response.status_code == 400
            else "repeated_forbidden_access"
        )

        actor_key = getattr(user, "id", None) or request.META.get("REMOTE_ADDR", "anon")

        counter = increment_counter(
            key(label, str(actor_key)),
            ttl_seconds=120,
        )

        if counter < 5:
            return

        decision = anomaly_service.evaluate(
            label,
            user=user,
            metadata={
                "count": counter,
                "window_seconds": 120,
            },
        )

        self._record(
            request,
            user,
            anomaly_service,
            decision,
            status_code=response.status_code,
        )

    def _detect_burst(self, request, user, anomaly_service):
        if not anomaly_service.flag_enabled(
            ANOMALY_RULE_BURST_ENABLED,
            user=user,
            default=True,
        ):
            return

        if not any(request.path.startswith(prefix) for prefix in self.sensitive_prefixes):
            return

        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return

        actor_key = getattr(user, "id", None) or request.META.get("REMOTE_ADDR", "anon")

        counter = increment_counter(
            key("burst", str(actor_key), request.path),
            ttl_seconds=60,
        )

        if counter < 20:
            return

        decision = anomaly_service.evaluate(
            "burst_sensitive_endpoint_access",
            user=user,
            metadata={
                "count": counter,
                "window_seconds": 60,
                "path": request.path,
            },
        )

        self._record(
            request,
            user,
            anomaly_service,
            decision,
            status_code=429,
        )

    def _detect_path_probing(self, request, user, anomaly_service):
        if not anomaly_service.flag_enabled(
            ANOMALY_RULE_PERMISSION_PROBING_ENABLED,
            user=user,
            default=True,
        ):
            return

        if not any(request.path.startswith(prefix) for prefix in self.probe_prefixes):
            return

        actor_key = getattr(user, "id", None) or request.META.get("REMOTE_ADDR", "anon")

        counter = increment_counter(
            key("path_probe", str(actor_key), request.path),
            ttl_seconds=300,
        )

        if counter < 10:
            return

        decision = anomaly_service.evaluate(
            "repeated_forbidden_access",
            user=user,
            metadata={
                "probe_path": request.path,
                "count": counter,
            },
        )

        self._record(
            request,
            user,
            anomaly_service,
            decision,
            status_code=403,
        )

    def _extract_resource(self, path: str):
        segments = [segment for segment in path.strip("/").split("/") if segment]

        if not segments:
            return None, None

        resource_type = segments[-1]
        resource_id = None

        if len(segments) >= 2 and self.RESOURCE_ID_PATTERN.match(segments[-1]):
            resource_type = segments[-2]
            resource_id = segments[-1]

        return resource_type, resource_id