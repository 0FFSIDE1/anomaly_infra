import re

from django.conf import settings

from anomaly_infra.constants import (
    ANOMALY_RULE_BURST_ENABLED,
    ANOMALY_RULE_CROSS_TENANT_ENABLED,
    ANOMALY_RULE_PERMISSION_PROBING_ENABLED,
)
from anomaly_infra.django.counters import increment_counter, key
from anomaly_infra.django.request import build_event_payload, get_ip
from anomaly_infra.django.service import get_anomaly_service


class RequestAnomalyMiddleware:
    RESOURCE_ID_PATTERN = re.compile(
        r"^\d+$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )

    def __init__(self, get_response):
        self.get_response = get_response
        version = getattr(settings, "ANOMALY_API_VERSION", "api/v1").strip("/")
        self.sensitive_prefixes = tuple(
            getattr(
                settings,
                "ANOMALY_SENSITIVE_PREFIXES",
                (
                    f"/{version}/auth/",
                    f"/{version}/account/",
                    f"/{version}/users/",
                    f"/{version}/invoice/",
                    f"/{version}/payments/",
                ),
            )
        )
        self.probe_prefixes = tuple(
            getattr(
                settings,
                "ANOMALY_PROBE_PREFIXES",
                ("/admin/", f"/{version}/account/roles/", f"/{version}/users/"),
            )
        )
        self.burst_threshold = int(getattr(settings, "ANOMALY_BURST_THRESHOLD", 20))
        self.burst_window_seconds = int(getattr(settings, "ANOMALY_BURST_WINDOW_SECONDS", 60))
        self.validation_failure_threshold = int(
            getattr(settings, "ANOMALY_VALIDATION_FAILURE_THRESHOLD", 5)
        )
        self.validation_failure_window_seconds = int(
            getattr(settings, "ANOMALY_VALIDATION_FAILURE_WINDOW_SECONDS", 120)
        )
        self.path_probe_threshold = int(getattr(settings, "ANOMALY_PATH_PROBE_THRESHOLD", 10))
        self.path_probe_window_seconds = int(
            getattr(settings, "ANOMALY_PATH_PROBE_WINDOW_SECONDS", 300)
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
        resource_type, resource_id = self._extract_resource(getattr(request, "path", "") or "")
        try:
            request.anomaly_resource_id = resource_id
        except Exception:
            pass

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
            ANOMALY_RULE_CROSS_TENANT_ENABLED, user=user, default=True
        ):
            return

        meta = getattr(request, "META", {}) or {}
        header_tenant = meta.get("HTTP_X_TENANT") or meta.get("HTTP_X_TENANT_ID")
        tenant = getattr(request, "tenant", None)
        request_tenant = getattr(tenant, "id", None) or getattr(tenant, "name", None) or getattr(
            request, "tenant_id", None
        )

        if header_tenant and request_tenant and str(header_tenant) != str(request_tenant):
            decision = anomaly_service.evaluate(
                "cross_tenant_access_attempt",
                user=user,
                metadata={"header_tenant": str(header_tenant), "request_tenant": str(request_tenant)},
                user_message="Invalid request.",
            )
            self._record(request, user, anomaly_service, decision, status_code=400)

    def _detect_response_pattern(self, request, response, user, anomaly_service):
        status_code = getattr(response, "status_code", None)
        if status_code not in {400, 403}:
            return

        if status_code == 403 and not anomaly_service.flag_enabled(
            ANOMALY_RULE_PERMISSION_PROBING_ENABLED, user=user, default=True
        ):
            return

        label = "repeated_validation_failures" if status_code == 400 else "repeated_forbidden_access"
        threshold = self.validation_failure_threshold
        window = self.validation_failure_window_seconds
        actor_key = self._actor_key(request, user)
        counter = increment_counter(key(label, actor_key), ttl_seconds=window)

        if counter < threshold:
            return

        decision = anomaly_service.evaluate(
            label, user=user, metadata={"count": counter, "window_seconds": window}
        )
        self._record(request, user, anomaly_service, decision, status_code=status_code)

    def _detect_burst(self, request, user, anomaly_service):
        if not anomaly_service.flag_enabled(ANOMALY_RULE_BURST_ENABLED, user=user, default=True):
            return

        path = getattr(request, "path", "") or ""
        method = (getattr(request, "method", "") or "").upper()
        if not any(path.startswith(prefix) for prefix in self.sensitive_prefixes):
            return
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return

        actor_key = self._actor_key(request, user)
        counter = increment_counter(key("burst", actor_key, path), ttl_seconds=self.burst_window_seconds)
        if counter < self.burst_threshold:
            return

        decision = anomaly_service.evaluate(
            "burst_sensitive_endpoint_access",
            user=user,
            metadata={"count": counter, "window_seconds": self.burst_window_seconds, "path": path},
        )
        self._record(request, user, anomaly_service, decision, status_code=429)

    def _detect_path_probing(self, request, user, anomaly_service):
        if not anomaly_service.flag_enabled(
            ANOMALY_RULE_PERMISSION_PROBING_ENABLED, user=user, default=True
        ):
            return

        path = getattr(request, "path", "") or ""
        if not any(path.startswith(prefix) for prefix in self.probe_prefixes):
            return

        actor_key = self._actor_key(request, user)
        counter = increment_counter(key("path_probe", actor_key, path), ttl_seconds=self.path_probe_window_seconds)
        if counter < self.path_probe_threshold:
            return

        decision = anomaly_service.evaluate(
            "path_probing", user=user, metadata={"probe_path": path, "count": counter}
        )
        self._record(request, user, anomaly_service, decision, status_code=403)

    def _actor_key(self, request, user) -> str:
        user_id = getattr(user, "id", None)
        if user_id is not None:
            return f"user:{user_id}"
        return f"ip:{get_ip(request) or 'anon'}"

    def _extract_resource(self, path: str):
        segments = [segment for segment in str(path).strip("/").split("/") if segment]
        if not segments:
            return None, None

        resource_type = segments[-1][:100]
        resource_id = None
        if len(segments) >= 2 and self.RESOURCE_ID_PATTERN.match(segments[-1]):
            resource_type = segments[-2][:100]
            resource_id = segments[-1][:120]
        return resource_type, resource_id
