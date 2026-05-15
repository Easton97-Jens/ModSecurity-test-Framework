"""Connector test adapter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Mapping


class ConnectorAdapter(ABC):
    """Abstract interface for connector-specific test adapters."""

    @abstractmethod
    def prepare(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def start(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def reload(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def apply_config(self, config: Mapping[str, Any]) -> None:
        raise NotImplementedError

    @abstractmethod
    def apply_rules(self, rules: str) -> None:
        raise NotImplementedError

    @abstractmethod
    def endpoint(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def send_request(self, request: Mapping[str, Any]) -> Any:
        raise NotImplementedError

    @abstractmethod
    def collect_artifacts(self) -> Mapping[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def cleanup(self) -> None:
        raise NotImplementedError
