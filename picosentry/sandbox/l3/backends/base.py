from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from picosentry.sandbox.l3.models import SandboxEvent, Verdict

if TYPE_CHECKING:
    from picosentry.sandbox.l3.models import Policy, SandboxResult
    from picosentry.sandbox.l3.session import SandboxSession


def compute_verdict(events: list[SandboxEvent], exit_code: int | None) -> Verdict:
    """Event-driven verdict shared by every backend (WO5.0.0-019).

    The first deciding security event wins (KILL or DENY, in event order);
    a signal death (exit < -1) with no deciding event is a KILL
    (WO5.0.0-018 item 8: subprocess used to ALLOW exit -11 with no events);
    a command that merely exits nonzero (grep exit 2, npm audit exit 1) is
    NOT a policy violation — ALLOW.
    """
    for event in events:
        if event.verdict == Verdict.KILL:
            return Verdict.KILL
        if event.verdict == Verdict.DENY:
            return Verdict.DENY
    if exit_code is not None and exit_code < -1:
        return Verdict.KILL
    return Verdict.ALLOW


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
