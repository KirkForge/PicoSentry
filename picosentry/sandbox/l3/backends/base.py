
from __future__ import annotations

from abc import ABC, abstractmethod

from picosentry.sandbox.l3.models import Policy, SandboxResult


class SandboxBackend(ABC):

    @abstractmethod
    def run(
        self,
        command: list[str],
        policy: Policy,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict | None = None,
    ) -> SandboxResult:
        ...

    @abstractmethod
    def is_available(self) -> bool:
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    def isolation_level(self) -> str:
        return "observational_only"

    @property
    def enforcement_guarantee(self) -> str:
        return "best_effort"
