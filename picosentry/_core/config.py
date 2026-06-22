from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger("picosentry._core.config")


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

    # The default key the serve-mode settings module ships with, plus the
    # other "obvious placeholder" strings that show up in tutorials and
    # leaked config examples.  Any of these in the active secret key is a
    # bug, in production OR development — there is no scenario where a
    # code path that signs JWTs or hashes passwords should accept one of
    # these.  ALLOW_INSECURE_SECRET=true is the explicit escape hatch for
    # local dev work that hasn't picked a real key yet.
    _WEAK_SECRET_DENYLIST = frozenset(
        {
            "",
            "change-me-in-production",
            "changeme",
            "default",
            "secret",
            "password",
            "please-change-me",
            "your-secret-key",
            "your-secret-key-here",
        }
    )
    _MIN_SECRET_KEY_LENGTH = 32

    insecure_secret_override = os.environ.get("ALLOW_INSECURE_SECRET", "").lower() in ("true", "1", "yes")
    if not insecure_secret_override:
        if secret_key in _WEAK_SECRET_DENYLIST:
            violations.append(
                SecurityViolation(
                    check="secret_key",
                    message=(
                        "Secret key is empty or uses a well-known placeholder. "
                        "Set a real key via the SECRET_KEY env var, or "
                        "ALLOW_INSECURE_SECRET=true for local dev only."
                    ),
                    severity="ERROR",
                )
            )
        elif len(secret_key) < _MIN_SECRET_KEY_LENGTH:
            violations.append(
                SecurityViolation(
                    check="secret_key_length",
                    message=(
                        f"Secret key is {len(secret_key)} bytes; minimum is "
                        f"{_MIN_SECRET_KEY_LENGTH}. Short keys are brute-forceable."
                    ),
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

    for custom_check in checks or []:
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
]
