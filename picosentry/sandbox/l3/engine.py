"""L3 Execution Sandbox — engine.

The `deterministic` parameter controls whether run_id, timestamp, and
duration_ms are included in the output. When deterministic=True (the default
for reproducible output), these fields are omitted. When deterministic=False,
they are filled in with real values.

Backend selection:
    - ``auto``: Auto-detect best available backend (default).
    - ``seccomp-bpf``: Linux kernel-level enforcement via libseccomp.
    - ``seatbelt``: macOS sandbox-exec enforcement.
    - ``subprocess``: Universal observational-only backend.

When a specific backend is requested but unavailable, the engine **fails
closed** — it raises BackendUnavailableError rather than silently degrading
to a weaker backend. Use ``allow_degraded=True`` (or the env var
``PICODOME_ALLOW_DEGRADED=1``) to opt into subprocess fallback explicitly.

The subprocess backend is **observational only** — it detects suspicious
patterns in output but does not prevent syscalls. Results from the
subprocess backend include ``isolation_level="observational_only"`` and
``enforcement_guarantee="best_effort"`` to make this distinction clear.
"""

from __future__ import annotations

import logging
import os
import platform
import threading

from picosentry.sandbox.l3.backends.base import SandboxBackend
from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend
from picosentry.sandbox.l3.models import Policy, SandboxResult
from picosentry.sandbox.l3.policy import default_policy
from picosentry.sandbox.l3.policy_hash import policy_hash
from picosentry.sandbox.models import _generate_run_id, _generate_timestamp

logger = logging.getLogger("picodome.l3.engine")


class BackendUnavailableError(RuntimeError):
    """Raised when a requested backend is not available on this system.

    This is a fail-closed error: the engine refuses to silently degrade
    to a weaker backend. The caller must explicitly opt in via
    ``allow_degraded=True`` or ``PICODOME_ALLOW_DEGRADED=1``.
    """

    def __init__(
        self,
        backend_name: str,
        reason: str,
        available_backends: list[str] | None = None,
    ) -> None:
        self.backend_name = backend_name
        self.reason = reason
        self.available_backends = available_backends or []
        super().__init__(
            f"Backend '{backend_name}' unavailable: {reason}. "
            f"Available: {self.available_backends or 'none'}. "
            f"Set PICODOME_ALLOW_DEGRADED=1 or pass allow_degraded=True "
            f"to opt into subprocess fallback."
        )


def _detect_backend(
    requested: str | None = None,
    allow_degraded: bool | None = None,
) -> SandboxBackend:
    """Select and initialise a sandbox backend.

    Args:
        requested: Explicit backend name (``"seccomp-bpf"``,
            ``"seatbelt"``, ``"subprocess"``, or ``None`` for auto).
        allow_degraded: If True, silently fall back to subprocess when
            the requested backend is unavailable. If None, reads
            ``PICODOME_ALLOW_DEGRADED`` env var (default: False).

    Returns:
        An initialised SandboxBackend.

    Raises:
        BackendUnavailableError: If the requested backend is unavailable
            and degraded mode is not allowed.
    """
    if allow_degraded is None:
        allow_degraded = os.environ.get("PICODOME_ALLOW_DEGRADED", "").lower() in ("1", "true", "yes")

    system = platform.system()
    available: list[str] = ["subprocess"]

    # Detect what's available
    seccomp_available = False
    seccomp_trace_available = False
    seatbelt_available = False

    if system == "Linux":
        try:
            from picosentry.sandbox.l3.backends.seccomp_backend import SeccompBackend

            seccomp_backend = SeccompBackend()
            if seccomp_backend.is_available():
                seccomp_available = True
                available.insert(0, "seccomp-bpf")
        except ImportError:
            pass
        except Exception:
            logger.debug("Seccomp backend check failed", exc_info=True)

        # Sibling trace backend: SCMP_ACT_LOG + /proc/<pid>/seccomp.
        # Explicit-only in v2.1.0 — appended, not inserted at the front.
        # See seccomp_trace_backend.py module docstring for the v2.1.0
        # limitation (no syscall args) and v2.2.0 plan.
        try:
            from picosentry.sandbox.l3.backends.seccomp_trace_backend import SeccompTraceBackend

            if SeccompTraceBackend().is_available():
                seccomp_trace_available = True
                available.append("seccomp-trace")
        except ImportError:
            pass
        except Exception:
            logger.debug("Seccomp trace backend check failed", exc_info=True)

    elif system == "Darwin":
        try:
            from picosentry.sandbox.l3.backends.seatbelt_backend import SeatbeltBackend

            seatbelt_backend = SeatbeltBackend()
            if seatbelt_backend.is_available():
                seatbelt_available = True
                available.insert(0, "seatbelt")
        except ImportError:
            pass
        except Exception:
            logger.debug("Seatbelt backend check failed", exc_info=True)

    # ── Explicit backend requested ───────────────────────────────────
    if requested is not None:
        requested = requested.lower().strip()

        if requested == "seccomp-bpf":
            if seccomp_available:
                from picosentry.sandbox.l3.backends.seccomp_backend import SeccompBackend

                logger.info("Using seccomp-bpf backend (explicitly requested)")
                return SeccompBackend()
            if allow_degraded:
                logger.warning("seccomp-bpf requested but unavailable — degrading to subprocess (allow_degraded=True)")
                return SubprocessBackend()
            raise BackendUnavailableError(
                "seccomp-bpf",
                "libseccomp not available on this system",
                available_backends=available,
            )

        if requested == "seccomp-trace":
            if seccomp_trace_available:
                from picosentry.sandbox.l3.backends.seccomp_trace_backend import SeccompTraceBackend

                logger.info("Using seccomp-trace backend (explicitly requested)")
                return SeccompTraceBackend()
            if allow_degraded:
                logger.warning(
                    "seccomp-trace requested but unavailable — degrading to subprocess (allow_degraded=True)"
                )
                return SubprocessBackend()
            raise BackendUnavailableError(
                "seccomp-trace",
                "SCMP_ACT_LOG not available on this system (requires libseccomp + Linux 3.5+ with CONFIG_SECCOMP_LOG=y)",
                available_backends=available,
            )

        if requested == "seatbelt":
            if seatbelt_available:
                from picosentry.sandbox.l3.backends.seatbelt_backend import SeatbeltBackend

                logger.info("Using seatbelt backend (explicitly requested)")
                return SeatbeltBackend()
            if allow_degraded:
                logger.warning("seatbelt requested but unavailable — degrading to subprocess (allow_degraded=True)")
                return SubprocessBackend()
            raise BackendUnavailableError(
                "seatbelt",
                "sandbox-exec not available on this system",
                available_backends=available,
            )

        if requested == "subprocess":
            logger.info("Using subprocess backend (explicitly requested)")
            return SubprocessBackend()

        raise BackendUnavailableError(
            requested,
            f"Unknown backend name '{requested}'",
            available_backends=available,
        )

    # ── Auto-detect ──────────────────────────────────────────────────
    if seccomp_available:
        from picosentry.sandbox.l3.backends.seccomp_backend import SeccompBackend

        logger.info("Using seccomp-bpf backend (auto-detected)")
        return SeccompBackend()

    if seatbelt_available:
        from picosentry.sandbox.l3.backends.seatbelt_backend import SeatbeltBackend

        logger.info("Using seatbelt backend (auto-detected)")
        return SeatbeltBackend()

    # No kernel backend available
    if allow_degraded:
        logger.warning(
            "No kernel-level sandbox available — subprocess "
            "backend provides OBSERVATIONAL ONLY analysis, "
            "not real enforcement. allow_degraded=True."
        )
        return SubprocessBackend()

    raise BackendUnavailableError(
        "auto",
        "No enforcement backend available on this platform. "
        f"System: {system}. libseccomp: {seccomp_available}, "
        f"sandbox-exec: {seatbelt_available}.",
        available_backends=available,
    )


_default_backend: SandboxBackend | None = None
_backend_lock = threading.Lock()


def get_backend() -> SandboxBackend:
    """Get the default sandbox backend (lazy init, thread-safe).

    Uses ``PICODOME_SANDBOX_BACKEND`` env var for explicit backend
    selection and ``PICODOME_ALLOW_DEGRADED`` for fallback opt-in.
    Thread-safe: uses a lock to prevent double initialization.
    """
    global _default_backend
    if _default_backend is None:
        with _backend_lock:
            if _default_backend is None:
                backend_name = os.environ.get("PICODOME_SANDBOX_BACKEND", None)
                _default_backend = _detect_backend(
                    requested=backend_name,
                    allow_degraded=None,  # reads from env inside
                )
    return _default_backend


def set_backend(
    backend: SandboxBackend,
    name: str | None = None,
) -> None:
    """Override the default backend.

    Args:
        backend: Backend instance to use.
        name: Optional backend name for logging.
    """
    global _default_backend
    _default_backend = backend
    logger.info("Backend override: %s", name or backend.name)


def reset_backend() -> None:
    """Reset the cached backend so next get_backend() re-detects."""
    global _default_backend
    _default_backend = None


def sandbox_run(
    command: list[str],
    policy: Policy | None = None,
    timeout: float | None = None,
    cwd: str | None = None,
    env: dict | None = None,
    backend: SandboxBackend | None = None,
    deterministic: bool = True,
    allow_degraded: bool | None = None,
) -> SandboxResult:
    """Run a command under sandbox policy.

    Args:
        command: Command and arguments to execute.
        policy: Sandbox policy (None = default deny-by-default).
        timeout: Wall-time limit in seconds.
        cwd: Working directory.
        env: Environment variables.
        backend: Override backend (None = auto-detect).
        deterministic: If True, omit run_id, timestamp, duration_ms
            for reproducible output. If False, fill with real values.
        allow_degraded: If True, allow fallback to subprocess when
            the requested backend is unavailable. If None, reads from
            PICODOME_ALLOW_DEGRADED env var.

    Returns:
        SandboxResult with events and overall verdict.

    Raises:
        BackendUnavailableError: If the requested backend is
            unavailable and allow_degraded is False.
    """
    if policy is None:
        policy = default_policy()

    if backend is None:
        if allow_degraded is not None:
            # Use explicit allow_degraded rather than env var
            be = _detect_backend(requested=None, allow_degraded=allow_degraded)
        else:
            be = get_backend()
    else:
        be = backend

    result = be.run(command, policy, timeout=timeout, cwd=cwd, env=env)

    # Compute evidence metadata
    p_hash = policy_hash(policy) if policy else ""
    p_version = policy.version if policy else ""

    # If deterministic, strip non-deterministic fields by rebuilding
    if deterministic:
        result = SandboxResult(
            command=result.command,
            overall_verdict=result.overall_verdict,
            exit_code=result.exit_code,
            events=result.events,
            policy_name=result.policy_name,
            backend_name=result.backend_name,
            isolation_level=result.isolation_level,
            enforcement_guarantee=result.enforcement_guarantee,
            degraded=result.degraded,
            stdout=result.stdout,
            stderr=result.stderr,
            backend=be.name,
            policy_hash=p_hash,
            policy_version=p_version,
        )
    else:
        # Fill in non-deterministic fields
        result = SandboxResult(
            run_id=_generate_run_id(),
            timestamp=_generate_timestamp(),
            command=result.command,
            overall_verdict=result.overall_verdict,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            events=result.events,
            policy_name=result.policy_name,
            backend_name=result.backend_name,
            isolation_level=result.isolation_level,
            enforcement_guarantee=result.enforcement_guarantee,
            degraded=result.degraded,
            stdout=result.stdout,
            stderr=result.stderr,
            backend=be.name,
            policy_hash=p_hash,
            policy_version=p_version,
        )

    logger.info(
        "L3 sandbox %s: verdict=%s exit=%d duration=%dms events=%d backend=%s isolation=%s enforcement=%s degraded=%s",
        result.run_id or "(deterministic)",
        result.overall_verdict.value,
        result.exit_code,
        result.duration_ms,
        len(result.events),
        result.backend_name or "unknown",
        result.isolation_level or "unknown",
        result.enforcement_guarantee or "unknown",
        result.degraded,
    )

    return result


class SandboxEngine:
    """High-level sandbox engine interface."""

    def __init__(self, backend: SandboxBackend | None = None):
        self._backend = backend

    @property
    def backend(self) -> SandboxBackend:
        if self._backend is None:
            self._backend = get_backend()
        return self._backend

    def run(
        self,
        command: list[str],
        policy: Policy | None = None,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict | None = None,
        deterministic: bool = True,
    ) -> SandboxResult:
        return sandbox_run(
            command,
            policy=policy,
            timeout=timeout,
            cwd=cwd,
            env=env,
            backend=self._backend,
            deterministic=deterministic,
        )
