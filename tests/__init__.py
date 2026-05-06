"""Local pytest support package for anomaly_infra.

Keeping this directory as an explicit package ensures DJANGO_SETTINGS_MODULE=
``tests.settings`` resolves to the repository's test settings instead of an
unrelated third-party ``tests`` namespace package that may be installed in the
active environment.
"""
