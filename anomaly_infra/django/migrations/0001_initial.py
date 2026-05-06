# Generated for anomaly-infra reusable Django integration.

import uuid
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="AnomalyEvent",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("anomaly_type", models.CharField(db_index=True, max_length=120)),
                ("category", models.CharField(db_index=True, max_length=40)),
                ("severity", models.CharField(db_index=True, max_length=20)),
                ("risk_score", models.PositiveSmallIntegerField(db_index=True, default=0)),
                ("tenant_id", models.CharField(blank=True, db_index=True, max_length=120, null=True)),
                ("tenant_name", models.CharField(blank=True, max_length=255, null=True)),
                ("path", models.CharField(blank=True, max_length=2048, null=True)),
                ("method", models.CharField(blank=True, max_length=12, null=True)),
                ("resource_type", models.CharField(blank=True, max_length=100, null=True)),
                ("resource_id", models.CharField(blank=True, max_length=120, null=True)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.TextField(blank=True, null=True)),
                ("device_id", models.CharField(blank=True, max_length=255, null=True)),
                ("request_id", models.CharField(blank=True, max_length=255, null=True)),
                ("status_code", models.IntegerField(blank=True, null=True)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("masked_payload", models.JSONField(blank=True, default=dict)),
                ("action_taken", models.CharField(db_index=True, default="log", max_length=40)),
                ("blocked", models.BooleanField(db_index=True, default=False)),
                ("resolved", models.BooleanField(db_index=True, default=False)),
                ("resolved_at", models.DateTimeField(blank=True, null=True)),
                ("notes", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="anomaly_events",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="anomalyevent",
            index=models.Index(fields=["category", "severity"], name="anomaly_inf_categor_c7599b_idx"),
        ),
        migrations.AddIndex(
            model_name="anomalyevent",
            index=models.Index(fields=["tenant_id", "created_at"], name="anomaly_inf_tenant__5c3910_idx"),
        ),
        migrations.AddIndex(
            model_name="anomalyevent",
            index=models.Index(fields=["anomaly_type", "created_at"], name="anomaly_inf_anomaly_491587_idx"),
        ),
        migrations.AddIndex(
            model_name="anomalyevent",
            index=models.Index(fields=["resolved", "created_at"], name="anomaly_inf_resolve_6629b2_idx"),
        ),
        migrations.AddIndex(
            model_name="anomalyevent",
            index=models.Index(fields=["action_taken", "created_at"], name="anomaly_inf_action__550bac_idx"),
        ),
    ]
