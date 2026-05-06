from abc import ABC, abstractmethod


class AnomalyEventStore(ABC):
    @abstractmethod
    def save(self, payload: dict):
        raise NotImplementedError


class AlertDispatcher(ABC):
    @abstractmethod
    def dispatch(self, event_id: str, payload: dict | None = None):
        raise NotImplementedError