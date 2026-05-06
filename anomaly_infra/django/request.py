from urllib.parse import urlparse

from anomaly_infra.sanitizer import mask_sensitive


def get_ip(request):
    if not request:
        return None

    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.META.get("REMOTE_ADDR")


def get_user_agent(request):
    if not request:
        return None

    return request.META.get("HTTP_USER_AGENT")


def request_meta(request):
    if not request:
        return {
            "device_id": None,
            "request_id": None,
            "request": {},
        }

    absolute_uri = ""

    if hasattr(request, "build_absolute_uri"):
        absolute_uri = request.build_absolute_uri()

    parsed = urlparse(absolute_uri)

    return {
        "device_id": request.META.get("HTTP_X_DEVICE_ID"),
        "request_id": request.META.get("HTTP_X_REQUEST_ID"),
        "request": {
            "resource": parsed.path or getattr(request, "path", None),
            "resource_id": getattr(request, "anomaly_resource_id", None),
            "request_id": request.META.get("HTTP_X_REQUEST_ID"),
            "device_id": request.META.get("HTTP_X_DEVICE_ID"),
            "method": getattr(request, "method", None),
        },
    }


def build_event_payload(
    decision,
    *,
    request=None,
    user=None,
    tenant=None,
    status_code=None,
    resource_type=None,
    resource_id=None,
    payload=None,
    blocked=False,
):
    meta = request_meta(request)

    tenant_id = getattr(tenant, "id", None) or getattr(request, "tenant_id", None)
    tenant_name = getattr(tenant, "name", None) or getattr(request, "tenant_name", None)

    return {
        "anomaly_type": decision.anomaly_type,
        "category": decision.category,
        "severity": decision.severity,
        "risk_score": decision.risk_score,
        "user": user if getattr(user, "is_authenticated", False) else None,
        "tenant_id": str(tenant_id) if tenant_id else None,
        "tenant_name": tenant_name,
        "path": getattr(request, "path", None),
        "method": getattr(request, "method", None),
        "resource_type": resource_type,
        "resource_id": str(resource_id) if resource_id is not None else None,
        "ip_address": get_ip(request),
        "user_agent": get_user_agent(request),
        "device_id": meta["device_id"],
        "request_id": meta["request_id"],
        "status_code": status_code,
        "metadata": {
            **decision.metadata,
            "request": meta["request"],
        },
        "masked_payload": mask_sensitive(payload or {}),
        "action_taken": decision.action_taken,
        "blocked": blocked,
    }