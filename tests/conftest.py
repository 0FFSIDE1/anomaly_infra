import pytest


class DummyFlags:
    def __init__(self, values=None):
        self.values = values or {}

    def enabled(self, flag, *, user=None, default=False):
        return self.values.get(flag, default)


@pytest.fixture(autouse=True)
def clear_cache_and_service(settings):
    from django.core.cache import cache
    from anomaly_infra.django.service import reset_anomaly_service

    cache.clear()
    reset_anomaly_service()
    yield
    cache.clear()
    reset_anomaly_service()
