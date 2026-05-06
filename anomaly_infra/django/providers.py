from __future__ import annotations

import logging
from copy import deepcopy

from django.conf import settings
from django.db import DEFAULT_DB_ALIAS, connections

from anomaly_infra.interfaces import AlertDispatcher, AnomalyEventStore
from anomaly_infra.sanitizer import mask_sensitive

logger = logging.getLogger(__name__)


class DjangoAnomalyEventStore(AnomalyEventStore):
    """
    Persist anomaly events through Django's ORM.

    By default, events are written through an autocommit connection when the
    caller is inside a transaction.atomic() block. This keeps anomaly audit
    records available even if the business transaction later rolls back.
    """

    def __init__(
        self,
        *,
        database: str = DEFAULT_DB_ALIAS,
        independent_database_alias: str | None = None,
        persist_outside_transactions: bool | None = None,
    ):
        self.database = database
        self.independent_database_alias = independent_database_alias
        self.persist_outside_transactions = persist_outside_transactions

    def save(self, payload: dict):
        from .models import AnomalyEvent

        using = self._database_alias()
        return AnomalyEvent.objects.using(using).create(**payload)

    def _database_alias(self) -> str:
        if not self._should_persist_outside_transactions():
            return self.database

        connection = connections[self.database]
        if not connection.in_atomic_block:
            return self.database

        return self._independent_alias()

    def _should_persist_outside_transactions(self) -> bool:
        if self.persist_outside_transactions is not None:
            return self.persist_outside_transactions
        return bool(getattr(settings, "ANOMALY_PERSIST_EVENTS_OUTSIDE_TRANSACTIONS", True))

    def _independent_alias(self) -> str:
        configured_alias = self.independent_database_alias or getattr(
            settings, "ANOMALY_EVENT_DATABASE_ALIAS", None
        )
        if configured_alias:
            return configured_alias

        database_config = connections[self.database].settings_dict
        if self._is_in_memory_sqlite(database_config):
            logger.warning(
                "anomaly_independent_transaction_unsupported",
                extra={"database": self.database, "reason": "in_memory_sqlite"},
            )
            return self.database

        alias = f"{self.database}_anomaly_infra_events"
        if alias not in connections.databases:
            cloned_config = deepcopy(database_config)
            cloned_config["ATOMIC_REQUESTS"] = False
            cloned_config["CONN_MAX_AGE"] = 0
            connections.databases[alias] = cloned_config
        return alias

    @staticmethod
    def _is_in_memory_sqlite(database_config: dict) -> bool:
        if not str(database_config.get("ENGINE", "")).endswith("sqlite3"):
            return False
        name = str(database_config.get("NAME", ""))
        return name == ":memory:" or "mode=memory" in name


class LoggingAlertDispatcher(AlertDispatcher):
    def dispatch(self, event_id: str, payload: dict | None = None):
        safe_payload = mask_sensitive(payload or {})
        # Keep the log compact and sanitized; never emit raw request bodies.
        logger.warning(
            "anomaly_alert_dispatched",
            extra={
                "event_id": event_id,
                "anomaly_type": safe_payload.get("anomaly_type"),
                "severity": safe_payload.get("severity"),
                "risk_score": safe_payload.get("risk_score"),
            },
        )
