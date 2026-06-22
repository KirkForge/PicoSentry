from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

POLICY_VERSION = 1
KNOWN_POLICY_KEYS = frozenset(
    {
        "version",
        "fail_on",
        "allow_licenses",
        "deny_licenses",
        "deny_packages",
        "require",
        "waivers",
    }
)
VALID_LICENSES = frozenset(
    {
        "MIT",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "0BSD",
        "Unlicense",
        "CC0-1.0",
        "WTFPL",
        "Zlib",
        "GPL-2.0",
        "GPL-3.0",
        "AGPL-3.0",
        "LGPL-2.1",
        "LGPL-3.0",
        "MPL-2.0",
        "BSL-1.0",
        "Artistic-2.0",
        "EPL-2.0",
    }
)


def _parse_npm_label(label: str) -> tuple[str, str]:
    if label.startswith("@"):
        last_at = label.rfind("@")
        if last_at == 0:
            return (label, "")
        name = label[:last_at]
        version = label[last_at + 1 :]
        return (name, version)

    parts = label.split("@", 1)
    if len(parts) == 2:
        return (parts[0], parts[1])
    return (label, "")


@dataclass
class Waiver:
    id: str
    rule_id: str
    package: str  # package name or "name@version"
    reason: str
    owner: str  # email or team identifier
    expires: str  # ISO 8601 date
    ticket: str = ""  # Jira/GitHub issue link

    def is_expired(self) -> bool:
        try:
            expiry = datetime.fromisoformat(self.expires)
            return datetime.now(timezone.utc) > expiry.astimezone(timezone.utc)
        except (ValueError, TypeError):
            return True  # Invalid date = expired (fail-safe)

    def matches(self, rule_id: str, package: str) -> bool:
        if self.rule_id != rule_id:
            return False

        pkg_name, _ = _parse_npm_label(package)
        w_pkg_name, _ = _parse_npm_label(self.package)
        if w_pkg_name in ("*", pkg_name):
            return True

        return self.package == package

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "package": self.package,
            "reason": self.reason,
            "owner": self.owner,
            "expires": self.expires,
            "ticket": self.ticket,
        }

    @staticmethod
    def from_dict(d: dict) -> Waiver:
        return Waiver(
            id=d.get("id", ""),
            rule_id=d.get("rule_id", ""),
            package=d.get("package", ""),
            reason=d.get("reason", ""),
            owner=d.get("owner", ""),
            expires=d.get("expires", ""),
            ticket=d.get("ticket", ""),
        )


@dataclass
class PolicyViolation:
    violation_type: str  # "severity", "license", "deny_package", "requirement"
    severity: str = "ERROR"
    message: str = ""
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.violation_type,
            "severity": self.severity,
            "message": self.message,
            "detail": self.detail,
        }


@dataclass
class PolicyResult:
    passed: bool = True
    violations: list[PolicyViolation] = field(default_factory=list)
    waived_findings: int = 0
    expired_waivers: list[str] = field(default_factory=list)
    policy_digest: str = ""

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "violations": [v.to_dict() for v in self.violations],
            "waived_findings": self.waived_findings,
            "expired_waivers": self.expired_waivers,
            "policy_digest": self.policy_digest,
        }


__all__ = [
    "KNOWN_POLICY_KEYS",
    "POLICY_VERSION",
    "VALID_LICENSES",
    "PolicyResult",
    "PolicyViolation",
    "Waiver",
    "_parse_npm_label",
]
