from __future__ import annotations

import logging
import os

logger = logging.getLogger("picosentry.enterprise")


ENV_ENTERPRISE_MODE = "PICOSENTRY_ENTERPRISE_MODE"


EXIT_RULE_ERROR = 4
EXIT_INVALID_POLICY = 5
EXIT_AUTH_OFF = 6
EXIT_INSECURE_CONFIG = 7


class EnterpriseViolation(Exception):
    def __init__(self, message: str, exit_code: int = EXIT_INSECURE_CONFIG) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def is_enterprise_mode() -> bool:
    return os.environ.get(ENV_ENTERPRISE_MODE, "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def require_enterprise(check: str, value: object, message: str = "") -> None:
    if not is_enterprise_mode():
        return

    default_messages = {
        "auth_not_off": "Enterprise mode requires authentication. Refusing to start with auth=off.",
        "host_not_any": "Enterprise mode requires explicit host binding. Refusing 0.0.0.0 default.",
        "version_pinned": "Enterprise mode requires pinned version, not 'latest'.",
        "fail_on_rule_error": "Enterprise mode requires --fail-on-rule-error.",
        "strict_config": "Enterprise mode rejects unknown config keys.",
        "policy_digest": "Enterprise mode requires policy digest in scan results.",
    }

    if check == "auth_not_off":
        if value == "off":
            raise EnterpriseViolation(
                message or default_messages["auth_not_off"],
                exit_code=EXIT_AUTH_OFF,
            )
    elif check == "host_not_any":
        if value in ("0.0.0.0", "::"):
            raise EnterpriseViolation(
                message or default_messages["host_not_any"],
                exit_code=EXIT_INSECURE_CONFIG,
            )
    elif check == "version_pinned":
        if value == "latest":
            raise EnterpriseViolation(
                message or default_messages["version_pinned"],
                exit_code=EXIT_INSECURE_CONFIG,
            )
    elif check == "fail_on_rule_error":
        if not value:
            raise EnterpriseViolation(
                message or default_messages["fail_on_rule_error"],
                exit_code=EXIT_INSECURE_CONFIG,
            )
    elif check == "strict_config":
        if value:
            raise EnterpriseViolation(
                message or default_messages["strict_config"],
                exit_code=EXIT_INSECURE_CONFIG,
            )
    elif check == "policy_digest" and not value:
        logger.warning("Enterprise mode: policy_digest is empty in scan result. Populating with default-policy digest.")


def enterprise_daemon_checks(auth_mode: str, host: str) -> list[str]:
    warnings: list[str] = []

    require_enterprise("auth_not_off", auth_mode)
    require_enterprise("host_not_any", host)

    if auth_mode == "token":
        warnings.append("Enterprise mode: token auth is accepted but OIDC is recommended for production deployments.")

    return warnings


def enterprise_scan_checks(
    fail_on_rule_error: bool,
    policy_digest: str = "",
    config_digest: str = "",
) -> list[str]:
    warnings: list[str] = []

    require_enterprise("fail_on_rule_error", fail_on_rule_error)

    if not policy_digest:
        warnings.append("Enterprise mode: policy_digest is empty. Default-policy digest will be populated.")
    if not config_digest:
        warnings.append("Enterprise mode: config_digest is empty. Config digest will be populated from scan inputs.")

    return warnings
