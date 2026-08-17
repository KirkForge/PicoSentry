from __future__ import annotations

import logging
import os
import platform
import threading

import re

from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend
from picosentry.sandbox.l3.models import Policy, SandboxResult
from picosentry.sandbox.l3.policy import default_policy
from picosentry.sandbox.l3.policy_hash import policy_hash
from picosentry.sandbox.l3.session import run_session
from picosentry.sandbox.models import _generate_run_id, _generate_timestamp
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from picosentry.sandbox.l3.backends.base import SandboxBackend

logger = logging.getLogger("picodome.l3.engine")

# Env vars that must never leak into sandboxed children. Matches the denylist
# used by the HTTP scan path (serve/api/routers/scans.py) plus pattern-based
# stripping for anything that looks like a secret/password/token/key.
_ENV_DENYLIST: frozenset[str] = frozenset(
    {
        "SECRET_KEY",
        "DATABASE_URL",
        "PICOSHOGUN_SECRET_KEY",
        "PICODOME_API_TOKENS",
        "PICOWATCH_API_KEY",
        "PICOSHOGUN_REDIS_URL",
        "PICODOME_REDIS_URL",
        "SHOGUN_DATABASE_URL",
        "PICOSHOGUN_DATABASE_URL",
        "PICODOME_POLICY_SIGNING_KEY",
        "DISCORD_WEBHOOK_URL",
        "SLACK_WEBHOOK_URL",
        "PICOSHOGUN_SMTP_PASSWORD",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
        "GITHUB_TOKEN",
    }
)

_ENV_DENY_PATTERNS: tuple[re.Pattern[str], ...] = (re.compile(r"(_SECRET|_PASSWORD|_TOKEN|_KEY)$", re.IGNORECASE),)


def _strip_env(env: dict[str, str]) -> dict[str, str]:
    """Return a copy of *env* with secret-bearing keys removed."""
    stripped: dict[str, str] = {}
    for key, value in env.items():
        if key in _ENV_DENYLIST:
            logger.debug("Stripping env var %s from sandbox child", key)
            continue
        if any(pat.search(key) for pat in _ENV_DENY_PATTERNS):
            logger.debug("Stripping env var %s from sandbox child (pattern match)", key)
            continue
        stripped[key] = value
    return stripped


class BackendUnavailableError(RuntimeError):
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


class BackendRegistry:
    """Lightweight, per-process cache of detected backends.

    Unlike the previous module-level singleton, this registry is intentionally
    small and stateless except for the cached backend instance. Each call site
    receives its own :class:`~SandboxSession`, so resource ownership remains
    with the session, not with the registry.
    """

    def __init__(self) -> None:
        self._default_backend: SandboxBackend | None = None
        self._lock = threading.Lock()

    def get(self, allow_degraded: bool | None = None) -> SandboxBackend:
        if self._default_backend is None:
            with self._lock:
                if self._default_backend is None:
                    backend_name = os.environ.get("PICODOME_SANDBOX_BACKEND", None)
                    self._default_backend = _detect_backend(
                        requested=backend_name,
                        allow_degraded=allow_degraded,
                    )
        return self._default_backend

    def set(self, backend: SandboxBackend, name: str | None = None) -> None:
        with self._lock:
            self._default_backend = backend
        logger.info("Backend override: %s", name or backend.name)

    def reset(self) -> None:
        with self._lock:
            self._default_backend = None


_registry = BackendRegistry()


# Backward-compatible module-level helpers
def get_backend(allow_degraded: bool | None = None) -> SandboxBackend:
    return _registry.get(allow_degraded=allow_degraded)


def set_backend(
    backend: SandboxBackend,
    name: str | None = None,
) -> None:
    _registry.set(backend, name=name)


def reset_backend() -> None:
    _registry.reset()


def _detect_backend(
    requested: str | None = None,
    allow_degraded: bool | None = None,
) -> SandboxBackend:
    if allow_degraded is None:
        allow_degraded = os.environ.get("PICODOME_ALLOW_DEGRADED", "").lower() in ("1", "true", "yes")
    if allow_degraded:
        env_mode = os.environ.get("PICODOME_ENV", os.environ.get("PICOSHOGUN_ENV", "development"))
        if env_mode in ("production", "staging"):
            logger.critical(
                "Security: PICODOME_ALLOW_DEGRADED ignored in %s — degraded backends not permitted",
                env_mode,
            )
            allow_degraded = False

    system = platform.system()
    available: list[str] = ["subprocess"]

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
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
            logger.debug("Seccomp backend check failed", exc_info=True)

        try:
            from picosentry.sandbox.l3.backends.seccomp_trace_backend import SeccompTraceBackend

            if SeccompTraceBackend().is_available():
                seccomp_trace_available = True
                available.append("seccomp-trace")
        except ImportError:
            pass
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
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
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
            logger.debug("Seatbelt backend check failed", exc_info=True)

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
                (
                    "SCMP_ACT_LOG not available on this system "
                    "(requires libseccomp + Linux 3.5+ with CONFIG_SECCOMP_LOG=y)"
                ),
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

        if requested == "landlock":
            # Explicit-selection only: NOT in the auto-detect path — the landlock
            # kernel feature (CONFIG_LSM + >= 5.13) is less common than libseccomp,
            # so auto-picking it would flip behavior between hosts.
            from picosentry.sandbox.l3.backends.landlock_backend import LandlockBackend

            landlock_backend = LandlockBackend()
            if landlock_backend.is_available():
                logger.info("Using landlock backend (explicitly requested)")
                return landlock_backend
            if allow_degraded:
                logger.warning("landlock requested but unavailable — degrading to subprocess (allow_degraded=True)")
                return SubprocessBackend()
            raise BackendUnavailableError(
                "landlock",
                "landlock not available (requires Linux >= 5.13 with landlock LSM enabled)",
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

    if seccomp_available:
        from picosentry.sandbox.l3.backends.seccomp_backend import SeccompBackend

        logger.info("Using seccomp-bpf backend (auto-detected)")
        return SeccompBackend()

    if seatbelt_available:
        from picosentry.sandbox.l3.backends.seatbelt_backend import SeatbeltBackend

        logger.info("Using seatbelt backend (auto-detected)")
        return SeatbeltBackend()

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
    if policy is None:
        policy = default_policy()

    # env IS the child's complete environment — backends never merge it over
    # os.environ (that would re-leak every stripped secret). Strip secret
    # patterns before the dict reaches any backend.
    env = _strip_env(dict(os.environ)) if env is None else _strip_env(env)

    if backend is None:
        if allow_degraded is not None:
            be = _detect_backend(requested=None, allow_degraded=allow_degraded)
        else:
            be = get_backend()
    else:
        be = backend

    result = run_session(
        backend=be,
        policy=policy,
        command=command,
        timeout=timeout,
        cwd=cwd,
        env=env,
    )

    p_hash = policy_hash(policy) if policy else ""
    p_version = policy.version if policy else ""

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
