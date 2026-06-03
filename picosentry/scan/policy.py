"""
Enterprise policy-as-code model for PicoSentry.

Supports:
- fail_on policies: severity thresholds, rule-specific gates
- allow_licenses / deny_licenses: license compliance policies
- deny_packages: blocked package names with version ranges
- waivers: time-bound exceptions with owner, reason, approval trail
- require: lockfile, integrity, package manager requirements

Deterministic: same policy file = same enforcement result.

Usage:
    from picosentry.scan.policy import Policy, Waiver, PolicyViolation
    policy = Policy.from_file(".picosentry-policy.yml")
    violations = policy.check(scan_result, package_licenses)
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from picosentry.scan.audit import audit
from picosentry.scan.crypto import (
    SignatureBundle,
    read_detached_signature,
    sign_content,
    verify_content,
    write_detached_signature,
)

logger = logging.getLogger("picosentry.policy")

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
    """Parse an npm package label into (name, version).

    Handles scoped packages: '@scope/name@1.2.3' -> ('@scope/name', '1.2.3')
    Handles unscoped: 'lodash@4.17.21' -> ('lodash', '4.17.21')
    Handles name-only: 'lodash' -> ('lodash', '')
    """
    if label.startswith("@"):
        # Scoped package: @scope/name@version or @scope/name
        # Find the last @ which separates name from version
        last_at = label.rfind("@")
        if last_at == 0:
            # Just @scope/name with no version
            return (label, "")
        name = label[:last_at]
        version = label[last_at + 1 :]
        return (name, version)
    else:
        # Unscoped: name@version or name
        parts = label.split("@", 1)
        if len(parts) == 2:
            return (parts[0], parts[1])
        return (label, "")


@dataclass
class Waiver:
    """A time-bound exception to a policy rule.

    Enterprise teams can waive specific findings with an expiration date,
    owner, reason, and optional ticket link. Expired waivers are NOT honored
    and findings will re-appear.
    """

    id: str
    rule_id: str
    package: str  # package name or "name@version"
    reason: str
    owner: str  # email or team identifier
    expires: str  # ISO 8601 date
    ticket: str = ""  # Jira/GitHub issue link

    def is_expired(self) -> bool:
        """Check if this waiver has expired."""
        try:
            expiry = datetime.fromisoformat(self.expires)
            return datetime.now(timezone.utc) > expiry.astimezone(timezone.utc)
        except (ValueError, TypeError):
            return True  # Invalid date = expired (fail-safe)

    def matches(self, rule_id: str, package: str) -> bool:
        """Check if this waiver applies to a finding."""
        if self.rule_id != rule_id:
            return False
        # Parse npm package labels correctly (handles scoped packages)
        pkg_name, _ = _parse_npm_label(package)
        w_pkg_name, _ = _parse_npm_label(self.package)
        if w_pkg_name == "*" or w_pkg_name == pkg_name:
            return True
        # Also try exact match for name@version
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
    """A policy rule that was violated during a scan."""

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
    """Result of applying policy to a scan."""

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


@dataclass
class Policy:
    """Enterprise policy definition for supply-chain governance.

    Loaded from .picosentry-policy.yml alongside .picosentry.yml config.
    Policies enforce organizational standards beyond what the scanner detects.
    """

    fail_on_severity: str = "high"  # minimum severity to fail
    fail_on_rules: list[str] = field(default_factory=list)  # specific rules that always fail
    allow_licenses: list[str] = field(default_factory=list)  # SPDX identifiers
    deny_licenses: list[str] = field(default_factory=list)
    deny_packages: list[str] = field(default_factory=list)  # "name" or "name@version"
    require_lockfile: bool = True
    require_integrity: bool = True
    require_provenance: bool = False
    # Update / network policy
    updates_enabled: bool = True  # False = hard-disable network updates
    updates_allowed_sources: list[str] = field(default_factory=list)  # allowlist of URLs
    updates_require_integrity: bool = True  # fail-closed on bad signatures
    corpus_require_signature: bool = True  # reject unsigned corpus packs (fail-closed default)
    waivers: list[Waiver] = field(default_factory=list)

    @property
    def digest(self) -> str:
        """Deterministic policy digest for audit trail."""
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
        """Load policy from a YAML (preferred) or JSON file.

        Returns default (permissive) policy if file not found.
        """
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
        """Return waivers that haven't expired.

        Also logs expired waivers for visibility.
        """
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
        """Check if a finding is covered by an active waiver."""
        for w in self.get_active_waivers():
            if w.matches(rule_id, package):
                return True, w
        return False, None

    def check_licenses(self, package_licenses: dict[str, str]) -> list[PolicyViolation]:
        """Check package licenses against allow/deny lists.

        Args:
            package_licenses: {package_name: license_identifier} mapping.

        Returns:
            List of policy violations.
        """
        violations: list[PolicyViolation] = []

        for pkg, lic in sorted(package_licenses.items()):
            lic_norm = lic.strip()

            # Deny list takes precedence
            if self.deny_licenses:
                for denied in self.deny_licenses:
                    # Exact SPDX identifier match (case-insensitive)
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
                    # Check allow list if no deny match
                    if self.allow_licenses:
                        allowed = False
                        for allowed_lic in self.allow_licenses:
                            # Exact SPDX identifier match (case-insensitive)
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
        """Parse package name from label, handling scoped packages.

        '@scope/name@1.2.3' -> '@scope/name'
        'lodash@4.17.21' -> 'lodash'
        'lodash' -> 'lodash'
        """
        if pkg.startswith("@"):
            # Scoped package: find last @ which separates name from version
            last_at = pkg.rfind("@")
            if last_at == 0:
                return pkg  # '@scope/name' with no version
            return pkg[:last_at]
        # Unscoped: name@version or name
        parts = pkg.split("@", 1)
        return parts[0] if len(parts) == 2 else pkg

    def check_packages(self, installed_packages: set[str]) -> list[PolicyViolation]:
        """Check installed packages against deny list.

        Handles scoped packages correctly: @scope/name@1.2.3
        is parsed as name=@scope/name, version=1.2.3.
        """
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

    def check_requirements(self, target: Path, scan_result: Any) -> list[PolicyViolation]:
        """Check environmental requirements."""
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
        """Apply the full policy to a scan result.

        Args:
            scan_result: ScanResult from engine.
            target: Target directory.
            package_licenses: {pkg: license} mapping (from L2-LICENSE-001).
            installed_packages: Set of installed package names.

        Returns:
            PolicyResult with violations, waivers, and pass/fail.
        """
        violations: list[PolicyViolation] = []

        # Check findings against severity + rule policies
        from picosentry.scan.models import SEVERITY_ORDER  # noqa: N811
        fail_level = SEVERITY_ORDER.get(self.fail_on_severity.lower(), 1)

        waived_count = 0
        for f in scan_result.findings:
            # Check if waived
            is_waived, waiver = self.is_finding_waived(f.rule_id, f.package)
            if is_waived:
                waived_count += 1
                continue

            # Check rule-specific fail
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

            # Check severity threshold
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

        # Check licenses
        if package_licenses:
            violations.extend(self.check_licenses(package_licenses))

        # Check deny packages
        if installed_packages:
            violations.extend(self.check_packages(installed_packages))

        # Check requirements
        violations.extend(self.check_requirements(target, scan_result))

        # Check for expired waivers
        expired = [w.id for w in self.waivers if w.is_expired()]

        # Audit policy application
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


def default_policy_template() -> str:
    """Return a YAML template for .picosentry-policy.yml."""
    return """# PicoSentry Enterprise Policy
# Place alongside .picosentry.yml in your project root.
# See docs for full schema reference.

version: 1

# Minimum severity to fail CI on (critical, high, medium, low, info)
fail_on:
  severity: high
  # Specific rules that always fail CI regardless of severity
  rules:
    # - L2-POST-001
    # - L2-CRED-001

# License compliance: allow-list or deny-list
# Use SPDX identifiers: MIT, Apache-2.0, GPL-3.0, etc.
allow_licenses:
  - MIT
  - Apache-2.0
  - BSD-2-Clause
  - BSD-3-Clause
  - ISC

# deny_licenses takes precedence over allow_licenses
# deny_licenses:
#   - GPL-3.0
#   - AGPL-3.0

# Block specific packages (exact name or name@version)
# deny_packages:
#   - event-stream@3.3.6
#   - left-pad
#   - malicious-package

# Environmental requirements
require:
  lockfile: true       # Require lockfile
  integrity: true      # Require integrity hashes
  provenance: false    # Require SLSA provenance (future)

# Waivers: time-bound exceptions with ownership
waivers: []
# Example:
# waivers:
#   - id: WAIVER-001
#     rule_id: L2-PROV-001
#     package: internal-tool
#     reason: "Private package with internal provenance"
#     owner: security@example.com
#     expires: "2026-09-01"
#     ticket: "https://github.com/org/repo/issues/123"
"""


def export_signed_policy(
    policy: Policy,
    output_path: Path,
    signer: str = "",
    sign_method: str = "",
    sign_secret_key: str = "",
    sign_password: str = "",
) -> str:
    """Export a policy as a signed JSON bundle for org-wide distribution.

    The bundle includes the policy content plus a signature block with
    signer identity, digest, and timestamp. Teams can import signed
    policies and verify they haven't been tampered with.

    Args:
        policy: The Policy to export.
        output_path: Where to write the bundle.
        signer: Identity string (email, key ID, team name).
        sign_method: If set, cryptographically sign ("sigstore" or "minisign").
        sign_secret_key: Path to minisign secret key (minisign only).
        sign_password: Password for minisign secret key.

    Returns:
        Bundle digest string.
    """
    import hashlib
    from datetime import datetime, timezone

    policy_dict = policy.to_dict()
    # Canonical JSON — no whitespace, sorted keys, same as importer uses
    policy_json = json.dumps(policy_dict, sort_keys=True, separators=(",", ":"))
    digest = f"sha256:{hashlib.sha256(policy_json.encode()).hexdigest()[:32]}"
    # Pretty-print for the file (human-readable bundle)
    pretty_json = json.dumps(policy_dict, sort_keys=True, indent=2)

    bundle = {
        "bundle_format": "1.0",
        "digest": digest,
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "signer": signer or "unsigned",
        "policy": policy_dict,
    }

    pretty_json = json.dumps(bundle, sort_keys=True, indent=2)
    output_path.write_text(pretty_json, encoding="utf-8")

    # Cryptographically sign the bundle if requested
    if sign_method:
        try:
            canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
            sig = sign_content(canonical.encode("utf-8"), sign_method, sign_secret_key, sign_password)
            write_detached_signature(sig, output_path)
            bundle["_crypto"] = sig.to_dict()
            logger.info(
                "Policy bundle cryptographically signed: provider=%s, identity=%s", sig.provider, sig.signer_identity
            )
        except ImportError as e:
            logger.warning("Cryptographic signing skipped: %s", e)
        except Exception as e:
            logger.error("Cryptographic signing failed: %s", e)

    logger.info("Exported signed policy bundle: %s (digest=%s)", output_path, digest)
    return digest


def import_policy_bundle(
    path: Path,
    verify: bool = True,
    verify_crypto: bool = False,
    public_key: str = "",
    offline: bool = False,
) -> Policy:
    """Import a signed policy bundle.

    Args:
        path: Path to the bundle JSON file.
        verify: If True, verify the digest.
        verify_crypto: If True, verify cryptographic signature.
        public_key: Path to minisign public key (minisign only).
        offline: If True, use offline Sigstore verification.

    Returns:
        The imported Policy.

    Raises:
        ValueError: If the bundle is invalid or verification fails.
    """
    import hashlib

    data = json.loads(path.read_text(encoding="utf-8"))

    if "policy" not in data:
        raise ValueError("Invalid policy bundle: missing 'policy' key")

    if verify and "digest" in data:
        policy_json = json.dumps(data["policy"], sort_keys=True, separators=(",", ":"))
        actual = f"sha256:{hashlib.sha256(policy_json.encode()).hexdigest()[:32]}"
        if data["digest"] != actual:
            raise ValueError(f"Policy bundle digest mismatch: expected={data['digest']} actual={actual}")

    # Verify cryptographic signature if requested
    if verify_crypto:
        sig_data = read_detached_signature(path)
        if sig_data is None:
            # Try embedded signature in bundle
            crypto_data = data.get("_crypto")
            if crypto_data and isinstance(crypto_data, dict):
                sig_data = SignatureBundle.from_dict(crypto_data)

        if sig_data is None:
            raise ValueError(
                "Cryptographic verification requested but no signature found. Use verify_crypto=False to skip."
            )

        if not sig_data.is_signed():
            raise ValueError(
                f"Policy bundle is not cryptographically signed "
                f"(provider={sig_data.provider}). Use verify_crypto=False to skip."
            )

        # Canonicalize the policy dict for verification
        canonical = json.dumps(data["policy"], sort_keys=True, separators=(",", ":"))
        try:
            ok = verify_content(
                canonical.encode("utf-8"),
                sig_data,
                public_key=public_key,
                offline=offline,
            )
            if not ok:
                raise ValueError(
                    "Cryptographic signature verification FAILED for policy bundle. "
                    "The bundle may have been tampered with."
                )
            logger.info(
                "Cryptographic signature verified: provider=%s, identity=%s",
                sig_data.provider,
                sig_data.signer_identity,
            )
        except ImportError as e:
            logger.warning("Cannot verify cryptographic signature: %s", e)
        except Exception as e:
            if "VerificationError" in type(e).__name__ or "FAILED" in str(e):
                raise
            raise ValueError(f"Cryptographic verification error: {e}") from e

    policy = Policy.from_dict(data["policy"])
    logger.info(
        "Imported policy bundle: signed by %s at %s",
        data.get("signer", "unsigned"),
        data.get("signed_at", "unknown"),
    )
    audit(
        "policy.import_bundle",
        target=str(path),
        metadata={
            "policy_digest": policy.digest,
            "signer": data.get("signer", "unsigned"),
            "signed_at": data.get("signed_at", "unknown"),
            "verified": verify,
        },
    )
    return policy


def policy_from_org(org_name: str) -> Policy:
    """Create a recommended default policy for common organization types.

    Args:
        org_name: One of 'startup', 'enterprise', 'oss', 'government'.

    Returns:
        A pre-configured Policy with sensible defaults.
    """
    defaults = {
        "startup": Policy(
            fail_on_severity="high",
            allow_licenses=["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"],
            require_lockfile=True,
            require_integrity=True,
        ),
        "enterprise": Policy(
            fail_on_severity="medium",
            fail_on_rules=["L2-POST-001", "L2-CRED-001", "L2-OBFS-001", "L2-OBFS-003"],
            allow_licenses=["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD"],
            deny_licenses=["GPL-3.0", "AGPL-3.0"],
            require_lockfile=True,
            require_integrity=True,
            require_provenance=False,
        ),
        "oss": Policy(
            fail_on_severity="critical",
            allow_licenses=[
                "MIT",
                "Apache-2.0",
                "BSD-2-Clause",
                "BSD-3-Clause",
                "ISC",
                "GPL-2.0",
                "GPL-3.0",
                "AGPL-3.0",
                "LGPL-2.1",
                "LGPL-3.0",
                "MPL-2.0",
                "0BSD",
                "Unlicense",
                "CC0-1.0",
            ],
            require_lockfile=True,
            require_integrity=False,
        ),
        "government": Policy(
            fail_on_severity="low",
            allow_licenses=["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD"],
            deny_licenses=["GPL-3.0", "AGPL-3.0", "UNLICENSED"],
            require_lockfile=True,
            require_integrity=True,
            require_provenance=True,
        ),
    }

    if org_name.lower() not in defaults:
        logger.warning("Unknown org type '%s'; using permissive default Policy", org_name)
    return defaults.get(org_name.lower(), Policy())
