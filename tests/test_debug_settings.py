from django.conf import settings


def test_installed_apps_debug():
    assert "anomaly_infra.django.apps.AnomalyInfraConfig" in settings.INSTALLED_APPS