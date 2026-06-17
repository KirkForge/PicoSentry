from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from picosentry.scan.audit import audit
from picosentry.scan.policy_pkg.models import (
    KNOWN_POLICY_KEYS,
    POLICY_VERSION,
    PolicyResult,
    PolicyViolation,
    Waiver,
)

logger = logging.getLogger("picosentry.policy")


@dataclass
class Policy:

    fail_on_severity: str = "high"  # minimum severity to fail
    fail_on_rules: list[str] = field(default_factory=list)  # specific rules that always fail
    allow_licenses: list[str] = field(default_factory=list)  # SPDX identifiers
    deny_licenses: list[str] = field(default_factory=list)
    deny_packages: list[str] = field(default_factory=list)  # "name" or "name@version"
    require_lockfile: bool = True
    require_integrity: bool = True
    require_provenance: bool = False

    updates_enabled: bool = True  # False = hard-disable network updates
    updates_allowed_sources: list[str] = field(default_factory=list)  # allowlist of URLs
    updates_require_integrity: bool = True  # fail-closed on bad signatures
    corpus_require_signature: bool = True  # reject unsigned corpus packs (fail-closed default)
    waivers: list[Waiver] = field(default_factory=list)

    @property
    def digest(self) -> str:
        raw = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "version": POLICY_VERSION,
            "fail_on": {
                "severity": self.fail_on_severity,
                "rules": self.fail_on_rules,
            },
            "allow_licenses": self.allow_licenses,
            "deny_licenses": self.deny_licenses,
            "deny_packages": self.deny_packages,
            "require": {
                "lockfile": self.require_lockfile,
                "integrity": self.require_integrity,
                "provenance": self.require_provenance,
            },
            "updates": {
                "enabled": self.updates_enabled,
                "allowed_sources": self.updates_allowed_sources,
                "require_integrity": self.updates_require_integrity,
                "corpus_require_signature": self.corpus_require_signature,
            },
            "waivers": [w.to_dict() for w in self.waivers],
        }

    @staticmethod
    def from_dict(data: dict) -> Policy:
        p = Policy()
        if "fail_on" in data and isinstance(data["fail_on"], dict):
            p.fail_on_severity = data["fail_on"].get("severity", "high")
            p.fail_on_rules = data["fail_on"].get("rules", [])
        if "allow_licenses" in data:
            p.allow_licenses = [str(lic).strip() for lic in data["allow_licenses"]]
        if "deny_licenses" in data:
            p.deny_licenses = [str(lic).strip() for lic in data["deny_licenses"]]
        if "deny_packages" in data:
            p.deny_packages = [str(pkg).strip() for pkg in data["deny_packages"]]
        if "require" in data and isinstance(data["require"], dict):
            req = data["require"]
            p.require_lockfile = req.get("lockfile", True)
            p.require_integrity = req.get("integrity", True)
            p.require_provenance = req.get("provenance", False)
        if "updates" in data and isinstance(data["updates"], dict):
            upd = data["updates"]
            p.updates_enabled = upd.get("enabled", True)
            p.updates_allowed_sources = upd.get("allowed_sources", [])
            p.updates_require_integrity = upd.get("require_integrity", True)
            p.corpus_require_signature = upd.get("corpus_require_signature", True)
        if "waivers" in data:
            p.waivers = [Waiver.from_dict(w) for w in data["waivers"]]
        return p

    @staticmethod
    def from_file(path: Path) -> Policy:
        if not path.is_file():
            return Policy()

        content = path.read_text(encoding="utf-8")
        try:
            import yaml

            data = yaml.safe_load(content)
        except ImportError:
            data = json.loads(content)

        if not isinstance(data, dict):
            logger.warning("Policy file %s is not a mapping, using defaults", path)
            return Policy()

        unknown = set(data.keys()) - KNOWN_POLICY_KEYS
        for key in sorted(unknown):
            logger.warning("Unknown policy key '%s' in %s", key, path)

        policy = Policy.from_dict(data)
        audit(
            "policy.load",
            target=str(path),
            metadata={"policy_digest": policy.digest, "source": "file"},
        )
        return policy

    def get_active_waivers(self) -> list[Waiver]:
        active = []
        for w in self.waivers:
            if w.is_expired():
                logger.info(
                    "Waiver expired: %s (rule=%s, package=%s, expired=%s)", w.id, w.rule_id, w.package, w.expires
                )
            else:
                active.append(w)
        return active

    def is_finding_waived(self, rule_id: str, package: str) -> tuple[bool, Waiver | None]:
        for w in self.get_active_waivers():
            if w.matches(rule_id, package):
                return True, w
        return False, None

    def check_licenses(self, package_licenses: dict[str, str]) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []

        for pkg, lic in sorted(package_licenses.items()):
            lic_norm = lic.strip()


            if self.deny_licenses:
                for denied in self.deny_licenses:

                    if denied.lower() == lic_norm.lower():
                        violations.append(
                            PolicyViolation(
                                violation_type="license",
                                severity="ERROR",
                                message=f"Package '{pkg}' uses denied license '{lic}'",
                                detail={"package": pkg, "license": lic, "denied": denied},
                            )
                        )
                        break
                else:

                    if self.allow_licenses:
                        allowed = False
                        for allowed_lic in self.allow_licenses:

                            if allowed_lic.lower() == lic_norm.lower():
                                allowed = True
                                break
                        if not allowed:
                            violations.append(
                                PolicyViolation(
                                    violation_type="license",
                                    severity="WARNING",
                                    message=f"Package '{pkg}' license '{lic}' not in allow list",
                                    detail={"package": pkg, "license": lic},
                                )
                            )

        return violations

    @staticmethod
    def _parse_package_name(pkg: str) -> str:
        if pkg.startswith("@"):

            last_at = pkg.rfind("@")
            if last_at == 0:
                return pkg  # '@scope/name' with no version
            return pkg[:last_at]

        parts = pkg.split("@", 1)
        return parts[0] if len(parts) == 2 else pkg

    def check_packages(self, installed_packages: set[str]) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []
        if not self.deny_packages:
            return violations

        for pkg in sorted(installed_packages):
            pkg_name = self._parse_package_name(pkg)
            for denied in self.deny_packages:
                d_name = self._parse_package_name(denied)
                if d_name and d_name == pkg_name:
                    violations.append(
                        PolicyViolation(
                            violation_type="deny_package",
                            severity="ERROR",
                            message=f"Package '{pkg}' is on the deny list",
                            detail={"package": pkg, "denied": denied},
                        )
                    )
                    break

        return violations

    def check_requirements(self, target: Path) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []

        if self.require_lockfile:
            has_lock = (
                (target / "package-lock.json").exists()
                or (target / "pnpm-lock.yaml").exists()
                or (target / "yarn.lock").exists()
            )
            if not has_lock:
                violations.append(
                    PolicyViolation(
                        violation_type="requirement",
                        severity="WARNING",
                        message="No lockfile found — dependency versions are not pinned",
                        detail={"required": "lockfile"},
                    )
                )

        if self.require_integrity:
            if (target / "package-lock.json").exists():
                pass  # npm lockfiles contain integrity by default
            elif not (target / "pnpm-lock.yaml").exists():
                violations.append(
                    PolicyViolation(
                        violation_type="requirement",
                        severity="WARNING",
                        message="No npm/pnpm lockfile — cannot verify package integrity",
                        detail={"required": "integrity"},
                    )
                )

        return violations

    def apply(
        self,
        scan_result: Any,
        target: Path,
        package_licenses: dict[str, str] | None = None,
        installed_packages: set[str] | None = None,
    ) -> PolicyResult:
        violations: list[PolicyViolation] = []


        from picosentry.scan.models import SEVERITY_ORDER
        fail_level = SEVERITY_ORDER.get(self.fail_on_severity.lower(), 1)

        waived_count = 0
        for f in scan_result.findings:

            is_waived, _waiver = self.is_finding_waived(f.rule_id, f.package)
            if is_waived:
                waived_count += 1
                continue


            if f.rule_id in self.fail_on_rules:
                violations.append(
                    PolicyViolation(
                        violation_type="severity",
                        severity="ERROR",
                        message=f"Finding violates fail-on rule: {f.rule_id}",
                        detail={"rule_id": f.rule_id, "package": f.package, "severity": f.severity.value},
                    )
                )
                continue


            f_level = SEVERITY_ORDER.get(f.severity.value.lower(), 4)
            if f_level <= fail_level:
                violations.append(
                    PolicyViolation(
                        violation_type="severity",
                        severity=f.severity.value,
                        message=f"Finding at or above fail-on severity ({self.fail_on_severity})",
                        detail={"rule_id": f.rule_id, "package": f.package, "severity": f.severity.value},
                    )
                )


        if package_licenses:
            violations.extend(self.check_licenses(package_licenses))


        if installed_packages:
            violations.extend(self.check_packages(installed_packages))


        violations.extend(self.check_requirements(target))


        expired = [w.id for w in self.waivers if w.is_expired()]


        audit(
            "policy.apply",
            target=str(target),
            metadata={
                "policy_digest": self.digest,
                "violations": len(violations),
                "waived": waived_count,
                "expired_waivers": len(expired),
                "fail_on_severity": self.fail_on_severity,
            },
        )

        return PolicyResult(
            passed=len(violations) == 0,
            violations=violations,
            waived_findings=waived_count,
            expired_waivers=expired,
            policy_digest=self.digest,
        )


__all__ = ["Policy"]
