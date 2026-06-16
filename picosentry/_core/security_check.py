"""Shared deployment security checker.

Detects dev-bypass environment variables that would weaken a production
deployment. Used by the Helm init container, CI lint, and can be invoked
from any PicoSentry component startup path.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
@dataclass(frozen=True)
class DeploymentFinding:
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    check: str
    message: str


# Environment variables that disable security gates. These are legitimate for
# local development but must never be set in a production deployment.
_DEV_BYPASS_VARS: tuple[tuple[str, str, str], ...] = (
    ("PICODOME_TLS_DEV", "HIGH", "Uses self-signed TLS certificates"),
    ("PICODOME_SKIP_SECURE_ASSERT", "HIGH", "Disables daemon secure-boot checks"),
    ("PICOSHOGUN_SKIP_SECURE_ASSERT", "HIGH", "Disables serve secure-boot checks"),
    ("PICOWATCH_SKIP_SECURE_ASSERT", "HIGH", "Disables watch secure-boot checks"),
    ("PICODOME_DEV_MODE", "CRITICAL", "Disables daemon authentication"),
)


def check_deployment_security(environ: dict[str, str] | None = None) -> list[DeploymentFinding]:
    """Return a list of findings for dev-bypass env vars that are set."""
    env = environ if environ is not None else dict(os.environ)
    findings: list[DeploymentFinding] = []

    for var, severity, reason in _DEV_BYPASS_VARS:
        if env.get(var) == "1":
            findings.append(
                DeploymentFinding(
                    severity=severity,
                    check=f"{var.lower().replace('_', '-')}-enabled",
                    message=f"{var}=1 is set — {reason}",
                )
            )

    # Enterprise mode should be active when the Helm chart enables it. If the
    # chart sets PICODOME_ENTERPRISE_MODE=1 but a dev-bypass is also set,
    # treat the bypass as CRITICAL because the deployment explicitly asked for
    # enterprise enforcement.
    enterprise_mode = env.get("PICODOME_ENTERPRISE_MODE") == "1"
    if enterprise_mode and env.get("PICODOME_TLS_DEV") == "1":
        findings.append(
            DeploymentFinding(
                severity="CRITICAL",
                check="enterprise-mode-with-tls-dev",
                message="PICODOME_ENTERPRISE_MODE=1 and PICODOME_TLS_DEV=1 are both set — enterprise mode rejects dev certs",
            )
        )

    # Check for weak placeholder secrets that should never survive a real deploy.
    weak_values = {"", "change-me", "changeme", "default", "secret", "password", "12345678"}
    for var in ("PICOSHOGUN_SECRET_KEY", "PICOWATCH_API_KEY", "PICODOME_API_TOKENS"):
        if var not in env:
            continue
        value = env[var].strip().lower()
        if value in weak_values:
            findings.append(
                DeploymentFinding(
                    severity="CRITICAL",
                    check=f"{var.lower().replace('_', '-')}-weak",
                    message=f"{var} uses a weak/placeholder value",
                )
            )

    return findings


def format_findings(findings: list[DeploymentFinding]) -> str:
    if not findings:
        return "✅ No deployment-security findings."
    lines = ["🔒 Deployment Security Check"]
    for f in findings:
        icon = {
            "CRITICAL": "🚨",
            "HIGH": "❌",
            "MEDIUM": "⚠️",
            "LOW": "💡",
            "INFO": "ℹ️",
        }.get(f.severity, "?")
        lines.append(f"{icon} [{f.severity:8s}] {f.check}: {f.message}")
    return "\n".join(lines)


def main(args: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="PicoSentry deployment security checker")
    parser.add_argument("--strict", action="store_true", help="Treat all findings as fatal")
    parser.add_argument("--json", action="store_true", help="Emit findings as JSON")
    parser.add_argument(
        "--env",
        action="append",
        default=[],
        help="Extra env var to check as KEY=VALUE (can be repeated)",
    )
    parsed = parser.parse_args(args)

    extra_env: dict[str, str] = {}
    for entry in parsed.env:
        if "=" in entry:
            key, value = entry.split("=", 1)
            extra_env[key] = value

    findings = check_deployment_security({**dict(os.environ), **extra_env})

    if parsed.json:
        import json

        print(json.dumps([{"severity": f.severity, "check": f.check, "message": f.message} for f in findings]))
    else:
        print(format_findings(findings))

    if not findings:
        return 0
    if parsed.strict or any(f.severity in ("CRITICAL", "HIGH") for f in findings):
        print("\n❌ FAIL — deployment-security check failed")
        return 1
    print("\n⚠️  WARN — non-fatal findings only")
    return 0


def assert_deployment_secure(environ: dict[str, str] | None = None) -> None:
    """Raise RuntimeError if any CRITICAL/HIGH finding is present."""
    findings = check_deployment_security(environ)
    fatal = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
    if fatal:
        raise RuntimeError(format_findings(fatal))


__all__ = [
    "DeploymentFinding",
    "assert_deployment_secure",
    "check_deployment_security",
    "format_findings",
    "main",
]


if __name__ == "__main__":
    sys.exit(main())
