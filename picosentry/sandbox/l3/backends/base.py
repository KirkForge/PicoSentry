from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from picosentry.sandbox.l3.models import Policy, SandboxResult
    from picosentry.sandbox.l3.session import SandboxSession


class SandboxBackend(ABC):
    @abstractmethod
    def run(
        self,
        command: list[str],
        policy: Policy,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict | None = None,
    ) -> SandboxResult: ...

    @abstractmethod
    def is_available(self) -> bool: ...

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    def isolation_level(self) -> str:
        return "observational_only"

    @property
    def enforcement_guarantee(self) -> str:
        return "best_effort"

    def run_in_session(self, session: SandboxSession) -> SandboxResult:
        """Execute within an explicit lifecycle session.

        The default implementation delegates to the legacy :meth:`run` API.
        Backends that need fine-grained resource tracking should override this
        method and register PIDs, file descriptors, and temporary files on
        ``session.resources`` so :class:`~SandboxSession` can clean them up.
        """
        return self.run(
            session.command,
            session.policy,
            timeout=session.timeout,
            cwd=session.cwd,
            env=session.env,
        )
