from __future__ import annotations

import contextlib
import enum
import logging
import os
import signal
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from picosentry.sandbox.l3.backends.base import SandboxBackend
    from picosentry.sandbox.l3.models import Policy, SandboxResult

logger = logging.getLogger("picodome.l3.session")


class SessionState(enum.Enum):
    """Explicit lifecycle states for a sandbox execution session.

    State transitions are allowed only in the forward direction:
    CREATED → STARTING → RUNNING → STOPPING → CLEANED.
    """

    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    CLEANED = "cleaned"


class SandboxSessionError(RuntimeError):
    """Raised when a session is used in an invalid state or cleanup fails."""


@dataclass
class _SessionResources:
    """Mutable resource bag owned by a single SandboxSession.

    Keeping this in a dedicated container makes it obvious what the session
    is responsible for releasing (file descriptors, child PIDs, temporary
    files, etc.) and prevents accidental sharing between sessions.
    """

    child_pid: int | None = None
    temp_files: list[str] = field(default_factory=list)
    open_fds: list[int] = field(default_factory=list)
    proc: object | None = None  # subprocess.Popen, if used by the backend

    def close_all(self) -> None:
        """Best-effort cleanup of every tracked resource."""
        for fd in self.open_fds:
            with contextlib.suppress(OSError):
                os.close(fd)
        self.open_fds.clear()

        if self.proc is not None:
            with contextlib.suppress(Exception):
                proc = self.proc
                # Duck-type the subprocess.Popen interface.
                poll = getattr(proc, "poll", None)
                kill = getattr(proc, "kill", None)
                wait = getattr(proc, "wait", None)
                if callable(poll) and callable(kill) and callable(wait) and poll() is None:
                    kill()
                    wait(timeout=2)
            self.proc = None

        if self.child_pid is not None:
            with contextlib.suppress(OSError):
                os.kill(self.child_pid, signal.SIGKILL)
                os.waitpid(self.child_pid, 0)
            self.child_pid = None

        for path in self.temp_files:
            with contextlib.suppress(OSError):
                os.unlink(path)
        self.temp_files.clear()


class SandboxSession:
    """Single-owner container for one sandbox execution lifecycle.

    A session is created for every run, holds the backend and policy, tracks
    the explicit :class:`SessionState`, and guarantees that all resources are
    released exactly once via :meth:`cleanup`.

    Backends receive the session instance so they can register child PIDs,
    temporary files, and file descriptors instead of performing their own
    ad-hoc cleanup. This makes the ownership line crisp: the session owns
    resources; the backend owns policy-to-syscall translation.
    """

    def __init__(
        self,
        backend: SandboxBackend,
        policy: Policy,
        command: list[str],
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict | None = None,
    ):
        self._backend = backend
        self._policy = policy
        self._command = list(command)
        self._timeout = timeout
        self._cwd = cwd
        self._env = env
        self._resources = _SessionResources()
        self._state = SessionState.CREATED
        self._result: SandboxResult | None = None
        self._lock = threading.Lock()

    @property
    def backend(self) -> SandboxBackend:
        return self._backend

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def command(self) -> list[str]:
        return list(self._command)

    @property
    def timeout(self) -> float | None:
        return self._timeout

    @property
    def cwd(self) -> str | None:
        return self._cwd

    @property
    def env(self) -> dict | None:
        return self._env

    @property
    def resources(self) -> _SessionResources:
        return self._resources

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def result(self) -> SandboxResult | None:
        return self._result

    def _transition(self, expected: SessionState, next_state: SessionState) -> None:
        with self._lock:
            if self._state != expected:
                raise SandboxSessionError(
                    f"Invalid session transition: expected {expected.value}, found {self._state.value}"
                )
            self._state = next_state

    def start(self) -> None:
        """Move the session from CREATED to RUNNING via STARTING.

        The backend's :meth:`~SandboxBackend.run_in_session` is invoked to
        perform any fork/exec, filter loading, or profile materialization.
        """
        self._transition(SessionState.CREATED, SessionState.STARTING)
        try:
            self._result = self._backend.run_in_session(self)
            self._transition(SessionState.STARTING, SessionState.RUNNING)
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        """Move the session to STOPPING and release tracked resources."""
        with self._lock:
            if self._state in (SessionState.STOPPING, SessionState.CLEANED):
                return
            if self._state not in (
                SessionState.CREATED,
                SessionState.STARTING,
                SessionState.RUNNING,
            ):
                raise SandboxSessionError(f"Cannot stop session in state {self._state.value}")
            self._state = SessionState.STOPPING

        try:
            self._resources.close_all()
        except Exception as e:
            logger.warning("SandboxSession cleanup error: %s", e)
        finally:
            with self._lock:
                self._state = SessionState.CLEANED

    def cleanup(self) -> None:
        """Idempotent alias for :meth:`stop`."""
        self.stop()

    def __enter__(self) -> SandboxSession:
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.cleanup()


def run_session(
    backend: SandboxBackend,
    policy: Policy,
    command: list[str],
    timeout: float | None = None,
    cwd: str | None = None,
    env: dict | None = None,
) -> SandboxResult:
    """Convenience helper: create, run, and clean up a single session."""
    session = SandboxSession(
        backend=backend,
        policy=policy,
        command=command,
        timeout=timeout,
        cwd=cwd,
        env=env,
    )
    try:
        session.start()
        result = session.result
        if result is None:
            raise SandboxSessionError("Backend did not produce a SandboxResult")
        return result
    finally:
        session.cleanup()
