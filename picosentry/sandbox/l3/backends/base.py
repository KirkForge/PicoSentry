"""Abstract base class for sandbox backends."""

from __future__ import annotations

from abc import ABC, abstractmethod

from picosentry.sandbox.l3.models import Policy, SandboxResult


class SandboxBackend(ABC):
    """Abstract sandbox backend interface."""

    @abstractmethod
    def run(
        self,
        command: list[str],
        policy: Policy,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict | None = None,
    ) -> SandboxResult:
        """Execute a command under the given policy."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this backend is usable on the current system."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable backend name."""
        ...

    @property
    def isolation_level(self) -> str:
        """Classification of isolation this backend provides.

        Values:
            - "kernel_enforced": Real syscall filtering (seccomp-bpf)
            - "os_policy_enforced": OS-level sandboxing (seatbelt)
            - "observational_only": Post-hoc pattern analysis (subprocess)
        """
        return "observational_only"

    @property
    def enforcement_guarantee(self) -> str:
        """How strong the enforcement guarantee is.

        Values:
            - "hard": Actions are blocked before they happen
            - "best_effort": Actions are detected after they happen
        """
        return "best_effort"
