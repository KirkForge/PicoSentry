
from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger("picosentry._core.config")


def from_env(key: str, default: str | None = None, required: bool = False) -> str | None:
    value = os.environ.get(key)
    if value is not None:
        return value
    if required:
        raise ValueError(f"Required environment variable {key} is not set")
    return default


def from_env_int(key: str, default: int = 0) -> int:
    value = os.environ.get(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        logger.warning("Invalid integer for %s=%r, using default %d", key, value, default)
        return default


def from_env_bool(key: str, default: bool = False) -> bool:
    value = os.environ.get(key)
    if value is None:
        return default
    return value.strip().lower() in ("true", "1", "yes")


@dataclass(frozen=True)
class SecurityViolation:

    check: str
    message: str
    severity: str = "ERROR"  # ERROR = block boot, WARN = allow but log


@runtime_checkable
class SecureBootCheck(Protocol):

    def check(self) -> SecurityViolation | None: ...


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
    violations: list[SecurityViolation] = []
    is_production = env in ("production", "staging")


    if is_production and (not secret_key or secret_key in ("changeme", "default", "secret")):
        violations.append(
            SecurityViolation(
                check="secret_key",
                message="Secret key is empty or default in production",
                severity="ERROR",
            )
        )


    if bind_host == "0.0.0.0":
        violations.append(
            SecurityViolation(
                check="bind_host",
                message="Binding to 0.0.0.0 — ensure firewall or auth is in place",
                severity="WARN",
            )
        )


    if cors_origin == "*":
        violations.append(
            SecurityViolation(
                check="cors_origin",
                message="CORS wildcard '*' allows any origin",
                severity="WARN",
            )
        )


    if is_production and debug:
        violations.append(
            SecurityViolation(
                check="debug_mode",
                message="Debug mode enabled in production",
                severity="ERROR",
            )
        )


    for custom_check in (checks or []):
        result = custom_check.check()
        if result is not None:
            violations.append(result)


    for v in violations:
        log_method = logging.ERROR if v.severity == "ERROR" else logging.WARNING
        logger.log(log_method, "Security: [%s] %s", v.check, v.message)


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


@runtime_checkable
class ConfigProtocol(Protocol):

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
