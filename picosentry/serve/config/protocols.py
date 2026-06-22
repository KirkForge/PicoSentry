from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ScannerService(Protocol):
    def scan(self, target: str, **kwargs: object) -> dict: ...


@runtime_checkable
class SandboxService(Protocol):
    def analyze(self, target: str, **kwargs: object) -> dict: ...


@runtime_checkable
class FirewallService(Protocol):
    def scan_prompt(self, text: str, **kwargs: object) -> dict: ...
    def validate_output(self, output: str, **kwargs: object) -> dict: ...


@runtime_checkable
class DashboardService(Protocol):
    def get_alerts(self, **kwargs: object) -> list: ...
    def get_events(self, **kwargs: object) -> list: ...
    def get_metrics(self) -> dict: ...


__all__ = [
    "DashboardService",
    "FirewallService",
    "SandboxService",
    "ScannerService",
]
