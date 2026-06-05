"""Shared configuration primitives — vendored from pico-core.

Provides:
- from_env: helper to read config values from environment variables
- assert_secure: startup gate that refuses to boot with insecure defaults
- ConfigProtocol: typing protocol for injected config (PR-02 pattern)
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger("picosentry._core.config")


# -- from_env helper -----------------------------------------------------------


def from_env(key: str, default: str | None = None, required: bool = False) -> str | None:
    """Read a configuration value from the environment.

    Args:
        key: Environment variable name.
        default: Default value if not set.
        required: If True, raise ValueError when not set and no default.

    Returns:
        The value from the environment, or default.
    """
    value = os.environ.get(key)
    if value is not None:
        return value
    if required:
        raise ValueError(f"Required environment variable {key} is not set")
    return default


def from_env_int(key: str, default: int = 0) -> int:
    """Read an integer configuration value from the environment."""
    value = os.environ.get(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        logger.warning("Invalid integer for %s=%r, using default %d", key, value, default)
        return default


def from_env_bool(key: str, default: bool = False) -> bool:
    """Read a boolean configuration value from the environment.

    Accepts: true/false, 1/0, yes/no (case-insensitive).
    """
    value = os.environ.get(key)
    if value is None:
        return default
    return value.strip().lower() in ("true", "1", "yes")


# -- Secure boot ----------------------------------------------------------------


@dataclass(frozen=True)
class SecurityViolation:
    """A single security violation found during startup gate check."""

    check: str
    message: str
    severity: str = "ERROR"  # ERROR = block boot, WARN = allow but log


@runtime_checkable
class SecureBootCheck(Protocol):
    """Protocol for custom startup gate checks.

    Each codebase registers its own checks (e.g. PicoWatch: API key length,
    PicoDome: mTLS cert presence).
    """

    def check(self) -> SecurityViolation | None: ...


# Standardized exit code for security violations
SECURITY_EXIT_CODE = 7


def assert_secure(
    checks: list[SecureBootCheck] | None = None,
    *,
    secret_key: str = "",
    bind_host: str = "127.0.0.1",
    cors_origin: str = "",
    debug: bool = False,
    env: str = "production",
    block_on_error: bool = True,
) -> list[SecurityViolation]:
    """Startup gate that refuses to boot with insecure defaults in production.

    Standardized checks:
    - secret_key not default/empty (when in production)
    - bind not 0.0.0.0 (when using API key)
    - CORS not wildcard *
    - debug off in production

    Each codebase registers its own checks via SecureBootCheck protocol.

    Args:
        checks: Additional codebase-specific checks to run.
        secret_key: The configured secret key.
        bind_host: The host to bind the server to.
        cors_origin: The CORS origin setting.
        debug: Whether debug mode is enabled.
        env: Environment name ('production', 'staging', 'development', 'test').
        block_on_error: If True, exit with SECURITY_EXIT_CODE on ERROR violations.

    Returns:
        List of SecurityViolation objects found.
    """
    violations: list[SecurityViolation] = []
    is_production = env in ("production", "staging")

    # 1. Secret key check (production only)
    if is_production and (not secret_key or secret_key in ("changeme", "default", "secret")):
        violations.append(
            SecurityViolation(
                check="secret_key",
                message="Secret key is empty or default in production",
                severity="ERROR",
            )
        )

    # 2. Bind host check (warn on 0.0.0.0 when using auth)
    if bind_host == "0.0.0.0":
        violations.append(
            SecurityViolation(
                check="bind_host",
                message="Binding to 0.0.0.0 — ensure firewall or auth is in place",
                severity="WARN",
            )
        )

    # 3. CORS wildcard check
    if cors_origin == "*":
        violations.append(
            SecurityViolation(
                check="cors_origin",
                message="CORS wildcard '*' allows any origin",
                severity="WARN",
            )
        )

    # 4. Debug in production check
    if is_production and debug:
        violations.append(
            SecurityViolation(
                check="debug_mode",
                message="Debug mode enabled in production",
                severity="ERROR",
            )
        )

    # Run additional codebase-specific checks
    for custom_check in (checks or []):
        result = custom_check.check()
        if result is not None:
            violations.append(result)

    # Log all violations
    for v in violations:
        log_method = logging.ERROR if v.severity == "ERROR" else logging.WARNING
        logger.log(log_method, "Security: [%s] %s", v.check, v.message)

    # Block on ERROR severity violations
    if block_on_error:
        errors = [v for v in violations if v.severity == "ERROR"]
        if errors:
            logger.critical(
                "Security gate: %d violation(s) — exiting with code %d",
                len(errors),
                SECURITY_EXIT_CODE,
            )
            sys.exit(SECURITY_EXIT_CODE)

    return violations


# -- ConfigProtocol ------------------------------------------------------------


@runtime_checkable
class ConfigProtocol(Protocol):
    """Protocol for injected configuration objects.

    Part of PR-02: break config star-topology by using Protocol typing
    so tests can inject mocks without reaching env vars.
    """

    def to_dict(self) -> dict[str, Any]: ...


__all__ = [
    "SECURITY_EXIT_CODE",
    "ConfigProtocol",
    "SecureBootCheck",
    "SecurityViolation",
    "assert_secure",
    "from_env",
    "from_env_bool",
    "from_env_int",
]
