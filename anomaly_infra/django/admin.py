from django.contrib import admin

from .models import AnomalyEvent


@admin.register(AnomalyEvent)
class AnomalyEventAdmin(admin.ModelAdmin):
    list_display = ("request_id", "created_at", "anomaly_type", "category", "severity", "risk_score", "tenant_name", "user", "blocked", "resolved")
    list_filter = ("category", "severity", "blocked", "resolved", "action_taken", "created_at")
    search_fields = ("request_id", "anomaly_type", "path", "resource_type", "resource_id", "user__username", "tenant_name", "ip_address")
    ordering = ("-created_at",)