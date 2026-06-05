"""Service Protocol interfaces for PicoShogun orchestration (PR-05).

Defines structural typing interfaces for the four PicoSeries services
that PicoShogun coordinates: PicoSentry (scanner), PicoDome (sandbox),
PicoWatch (firewall), and the dashboard.

These Protocols enable:
- Static type checking of service handoff points
- Runtime isinstance() checks for service validation
- Mock injection in tests without concrete dependencies
- Decoupled architecture: PicoShogun depends on interfaces, not implementations

Extracted from settings.py for separation of concerns.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ScannerService(Protocol):
    """Protocol for scanner service integration (PicoSentry handoff).

    PicoShogun calls ScannerService.scan() to trigger PicoSentry scans
    on a target package or codebase.
    """

    def scan(self, target: str, **kwargs: object) -> dict: ...


@runtime_checkable
class SandboxService(Protocol):
    """Protocol for sandbox service integration (PicoDome handoff).

    PicoShogun calls SandboxService.analyze() to trigger PicoDome sandbox
    analysis on a suspicious target identified by PicoSentry.
    """

    def analyze(self, target: str, **kwargs: object) -> dict: ...


@runtime_checkable
class FirewallService(Protocol):
    """Protocol for firewall service integration (PicoWatch handoff).

    PicoShogun calls FirewallService for both prompt scanning (L5)
    and output validation (L6).
    """

    def scan_prompt(self, text: str, **kwargs: object) -> dict: ...
    def validate_output(self, output: str, **kwargs: object) -> dict: ...


@runtime_checkable
class DashboardService(Protocol):
    """Protocol for the dashboard service (alerts, events, metrics).

    PicoShogun's dashboard aggregates data from all three scanners
    plus its own event bus and alert hub.
    """

    def get_alerts(self, **kwargs: object) -> list: ...
    def get_events(self, **kwargs: object) -> list: ...
    def get_metrics(self) -> dict: ...


__all__ = [
    "DashboardService",
    "FirewallService",
    "SandboxService",
    "ScannerService",
]
