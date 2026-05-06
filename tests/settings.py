from django.conf import settings
from dotenv import load_dotenv
import os

load_dotenv()

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "test-secret-key")
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "feature_flag_infra.django.apps.FeatureFlagInfraConfig",
    "anomaly_infra.django.apps.AnomalyInfraConfig",
]   

CACHES = {
    "default": {
        "BACKEND": os.getenv("CACHE_BACKEND", "django.core.cache.backends.locmem.LocMemCache"),
    }
}

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

ANOMALY_EVENT_TEST_DB = os.getenv("ANOMALY_EVENT_TEST_DB", "/tmp/anomaly_infra_event_test.sqlite3")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    },
    "anomaly_primary": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ANOMALY_EVENT_TEST_DB,
        "TEST": {"DEPENDENCIES": []},
    },
    "anomaly_events": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ANOMALY_EVENT_TEST_DB,
        "TEST": {"MIRROR": "anomaly_primary"},
    },
}

MIDDLEWARE = [
    "anomaly_infra.django.middleware.RequestAnomalyMiddleware",
]


DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

USE_TZ = True

DEFAULT_HOST = "testserver"
ALLOWED_HOSTS = [DEFAULT_HOST]
ROOT_URLCONF = "tests.urls"
ROOT_HOSTCONF = "tests.hosts"
