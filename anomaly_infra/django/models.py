import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class AnomalyEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    anomaly_type = models.CharField(max_length=120, db_index=True)
    category = models.CharField(max_length=40, db_index=True)
    severity = models.CharField(max_length=20, db_index=True)
    risk_score = models.PositiveIntegerField(default=0, db_index=True)

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="anomaly_events",
    )

    tenant_id = models.CharField(max_length=120, null=True, blank=True, db_index=True)
    tenant_name = models.CharField(max_length=255, null=True, blank=True)

    path = models.CharField(max_length=255, null=True, blank=True)
    method = models.CharField(max_length=12, null=True, blank=True)
    resource_type = models.CharField(max_length=100, null=True, blank=True)
    resource_id = models.CharField(max_length=120, null=True, blank=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    device_id = models.CharField(max_length=255, null=True, blank=True)
    request_id = models.CharField(max_length=255, null=True, blank=True)

    status_code = models.IntegerField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    masked_payload = models.JSONField(default=dict, blank=True)

    action_taken = models.CharField(max_length=40, default="log", db_index=True)
    blocked = models.BooleanField(default=False, db_index=True)

    resolved = models.BooleanField(default=False, db_index=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def mark_resolved(self, notes: str = ""):
        self.resolved = True
        self.resolved_at = timezone.now()
        self.notes = notes
        self.save(update_fields=["resolved", "resolved_at", "notes", "updated_at"])

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["category", "severity"]),
            models.Index(fields=["tenant_id", "created_at"]),
            models.Index(fields=["anomaly_type", "created_at"]),
            models.Index(fields=["resolved", "created_at"]),
        ]

    def __str__(self):
        return f"{self.anomaly_type} - {self.severity}"