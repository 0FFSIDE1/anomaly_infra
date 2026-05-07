from urllib.parse import urlparse

from django.conf import settings

from anomaly_infra.sanitizer import json_safe, mask_sensitive


def _meta(request):
    return getattr(request, "META", {}) or {}


def get_ip(request):
    if not request:
        return None

    meta = _meta(request)
    trust_forwarded = bool(getattr(settings, "ANOMALY_TRUST_X_FORWARDED_FOR", False))
    if trust_forwarded:
        forwarded = meta.get("HTTP_X_FORWARDED_FOR", "")
        if isinstance(forwarded, str) and forwarded.strip():
            return forwarded.split(",", 1)[0].strip() or None

    remote_addr = meta.get("REMOTE_ADDR")
    return str(remote_addr).strip() if remote_addr else None


def get_user_agent(request):
    if not request:
        return None
    agent = _meta(request).get("HTTP_USER_AGENT")
    return str(agent) if agent is not None else None


def request_meta(request):
    if not request:
        return {"device_id": None, "request_id": None, "request": {}}

    meta = _meta(request)
    path = getattr(request, "path", None)
    try:
        absolute_uri = request.build_absolute_uri() if hasattr(request, "build_absolute_uri") else ""
        parsed = urlparse(absolute_uri)
        if parsed.path:
            path = parsed.path
    except Exception:
        pass

    return {
        "device_id": meta.get("HTTP_X_DEVICE_ID"),
        "request_id": meta.get("HTTP_X_REQUEST_ID"),
        "request": {
            "resource": path,
            "resource_id": getattr(request, "anomaly_resource_id", None),
            "request_id": meta.get("HTTP_X_REQUEST_ID"),
            "device_id": meta.get("HTTP_X_DEVICE_ID"),
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
    safe_user = user if getattr(user, "is_authenticated", False) else None
    safe_user_id = getattr(safe_user, "pk", None)
    if safe_user_id is None:
        safe_user_id = getattr(safe_user, "id", None)
    safe_user_id = json_safe(safe_user_id)

    tenant_id = getattr(tenant, "id", None) or getattr(request, "tenant_id", None)
    tenant_name = getattr(tenant, "name", None) or getattr(request, "tenant_name", None)

    return {
        "anomaly_type": decision.anomaly_type,
        "category": decision.category,
        "severity": decision.severity,
        "risk_score": decision.risk_score,
        "user_id": safe_user_id,
        "tenant_id": str(tenant_id) if tenant_id is not None else None,
        "tenant_name": str(tenant_name) if tenant_name is not None else None,
        "path": getattr(request, "path", None),
        "method": getattr(request, "method", None),
        "resource_type": resource_type,
        "resource_id": str(resource_id) if resource_id is not None else None,
        "ip_address": get_ip(request),
        "user_agent": get_user_agent(request),
        "device_id": meta["device_id"],
        "request_id": meta["request_id"],
        "status_code": status_code,
        "metadata": json_safe(mask_sensitive({**(decision.metadata or {}), "request": meta["request"]})),
        "masked_payload": json_safe(mask_sensitive(payload or {})),
        "action_taken": decision.action_taken,
        "blocked": bool(blocked or decision.should_block),
    }
