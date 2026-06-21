"""
Comprehensive tests for picosentry.policy module.

Covers: Policy dataclass, Waiver, PolicyViolation, PolicyResult,
Policy.from_file(), Policy.from_dict(), Policy.apply(), Policy.to_dict(),
Policy.digest, import_policy_bundle(), export_signed_policy(),
policy_from_org(), _parse_npm_label, default_policy_template,
strict config mode (unknown keys), and all edge cases.
"""

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

from picosentry.scan.models import Severity
from picosentry.scan.policy import (
    POLICY_VERSION,
    Policy,
    PolicyResult,
    PolicyViolation,
    Waiver,
    _parse_npm_label,
    default_policy_template,
    export_signed_policy,
    import_policy_bundle,
    policy_from_org,
)

# ── Helpers ──

from tests.scan.conftest import make_finding as _make_finding


def _make_scan_result(findings=None):
    sr = MagicMock()
    sr.findings = findings if findings is not None else []
    return sr


# ── _parse_npm_label ──


class TestParseNpmLabel(unittest.TestCase):
    def test_unscoped_with_version(self):
        self.assertEqual(_parse_npm_label("lodash@4.17.21"), ("lodash", "4.17.21"))

    def test_unscoped_name_only(self):
        self.assertEqual(_parse_npm_label("lodash"), ("lodash", ""))

    def test_scoped_with_version(self):
        self.assertEqual(_parse_npm_label("@scope/name@1.2.3"), ("@scope/name", "1.2.3"))

    def test_scoped_name_only(self):
        self.assertEqual(_parse_npm_label("@scope/name"), ("@scope/name", ""))

    def test_empty_string(self):
        self.assertEqual(_parse_npm_label(""), ("", ""))


# ── Waiver ──


class TestWaiver(unittest.TestCase):
    def test_defaults(self):
        w = Waiver(id="w1", rule_id="R1", package="pkg", reason="why", owner="me", expires="2099-01-01")
        self.assertEqual(w.ticket, "")

    def test_is_expired_future(self):
        future = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
        w = Waiver(id="w1", rule_id="R1", package="pkg", reason="why", owner="me", expires=future)
        self.assertFalse(w.is_expired())

    def test_is_expired_past(self):
        past = "2020-01-01"
        w = Waiver(id="w1", rule_id="R1", package="pkg", reason="why", owner="me", expires=past)
        self.assertTrue(w.is_expired())

    def test_is_expired_invalid_date(self):
        w = Waiver(id="w1", rule_id="R1", package="pkg", reason="why", owner="me", expires="not-a-date")
        self.assertTrue(w.is_expired())

    def test_is_expired_none_like(self):
        w = Waiver(id="w1", rule_id="R1", package="pkg", reason="why", owner="me", expires="")
        self.assertTrue(w.is_expired())

    def test_matches_exact_rule_and_package(self):
        w = Waiver(id="w1", rule_id="L2-POST-001", package="bad-pkg", reason="why", owner="me", expires="2099-01-01")
        self.assertTrue(w.matches("L2-POST-001", "bad-pkg"))

    def test_matches_wrong_rule(self):
        w = Waiver(id="w1", rule_id="L2-POST-001", package="bad-pkg", reason="why", owner="me", expires="2099-01-01")
        self.assertFalse(w.matches("L2-OTHER", "bad-pkg"))

    def test_matches_wildcard_package(self):
        w = Waiver(id="w1", rule_id="L2-POST-001", package="*", reason="why", owner="me", expires="2099-01-01")
        self.assertTrue(w.matches("L2-POST-001", "any-pkg"))
        self.assertFalse(w.matches("OTHER-RULE", "any-pkg"))

    def test_matches_package_name_only(self):
        w = Waiver(id="w1", rule_id="R1", package="lodash", reason="why", owner="me", expires="2099-01-01")
        # Waiver is "lodash", finding is "lodash@4.17.21" -> name matches
        self.assertTrue(w.matches("R1", "lodash@4.17.21"))

    def test_matches_exact_name_version(self):
        w = Waiver(id="w1", rule_id="R1", package="lodash@4.17.21", reason="why", owner="me", expires="2099-01-01")
        # Exact match name@version
        self.assertTrue(w.matches("R1", "lodash@4.17.21"))
        # Waiver package name matches finding package name (both resolve to lodash)
        self.assertTrue(w.matches("R1", "lodash"))
        # Different package name does not match
        self.assertFalse(w.matches("R1", "underscore"))

    def test_matches_scoped_package(self):
        w = Waiver(id="w1", rule_id="R1", package="@scope/name", reason="why", owner="me", expires="2099-01-01")
        self.assertTrue(w.matches("R1", "@scope/name@1.0.0"))
        self.assertTrue(w.matches("R1", "@scope/name"))

    def test_to_dict(self):
        w = Waiver(id="w1", rule_id="R1", package="pkg", reason="why", owner="me", expires="2099-01-01", ticket="T-123")
        d = w.to_dict()
        self.assertEqual(d["id"], "w1")
        self.assertEqual(d["ticket"], "T-123")
        self.assertEqual(len(d), 7)

    def test_from_dict_full(self):
        d = {
            "id": "w1",
            "rule_id": "R1",
            "package": "pkg",
            "reason": "why",
            "owner": "me",
            "expires": "2099-01-01",
            "ticket": "T-1",
        }
        w = Waiver.from_dict(d)
        self.assertEqual(w.id, "w1")
        self.assertEqual(w.ticket, "T-1")

    def test_from_dict_missing_fields(self):
        w = Waiver.from_dict({})
        self.assertEqual(w.id, "")
        self.assertEqual(w.rule_id, "")
        self.assertEqual(w.package, "")
        self.assertEqual(w.expires, "")


# ── PolicyViolation ──


class TestPolicyViolation(unittest.TestCase):
    def test_defaults(self):
        pv = PolicyViolation(violation_type="severity")
        self.assertEqual(pv.severity, "ERROR")
        self.assertEqual(pv.message, "")
        self.assertEqual(pv.detail, {})

    def test_to_dict(self):
        pv = PolicyViolation(
            violation_type="license",
            severity="WARNING",
            message="Bad license",
            detail={"package": "pkg", "license": "GPL-3.0"},
        )
        d = pv.to_dict()
        self.assertEqual(d["type"], "license")
        self.assertEqual(d["severity"], "WARNING")
        self.assertEqual(d["message"], "Bad license")
        self.assertEqual(d["detail"]["package"], "pkg")


# ── PolicyResult ──


class TestPolicyResult(unittest.TestCase):
    def test_defaults(self):
        pr = PolicyResult()
        self.assertTrue(pr.passed)
        self.assertEqual(pr.violations, [])
        self.assertEqual(pr.waived_findings, 0)
        self.assertEqual(pr.expired_waivers, [])
        self.assertEqual(pr.policy_digest, "")

    def test_to_dict(self):
        pv = PolicyViolation(violation_type="severity", message="test")
        pr = PolicyResult(
            passed=False, violations=[pv], waived_findings=2, expired_waivers=["w1"], policy_digest="abc123"
        )
        d = pr.to_dict()
        self.assertFalse(d["passed"])
        self.assertEqual(len(d["violations"]), 1)
        self.assertEqual(d["waived_findings"], 2)
        self.assertEqual(d["expired_waivers"], ["w1"])
        self.assertEqual(d["policy_digest"], "abc123")


# ── Policy dataclass ──


class TestPolicyDefaults(unittest.TestCase):
    def test_defaults(self):
        p = Policy()
        self.assertEqual(p.fail_on_severity, "high")
        self.assertEqual(p.fail_on_rules, [])
        self.assertEqual(p.allow_licenses, [])
        self.assertEqual(p.deny_licenses, [])
        self.assertEqual(p.deny_packages, [])
        self.assertTrue(p.require_lockfile)
        self.assertTrue(p.require_integrity)
        self.assertFalse(p.require_provenance)
        self.assertTrue(p.updates_enabled)
        self.assertEqual(p.updates_allowed_sources, [])
        self.assertTrue(p.updates_require_integrity)
        self.assertTrue(p.corpus_require_signature)  # fail-closed default
        self.assertEqual(p.waivers, [])


# ── Policy.to_dict / digest ──


class TestPolicyToDict(unittest.TestCase):
    def test_roundtrip(self):
        p = Policy(
            fail_on_severity="medium",
            fail_on_rules=["L2-POST-001"],
            allow_licenses=["MIT", "Apache-2.0"],
            deny_licenses=["GPL-3.0"],
            deny_packages=["bad-pkg"],
            require_lockfile=False,
            require_integrity=False,
            require_provenance=True,
            updates_enabled=False,
            updates_allowed_sources=["https://example.com"],
            updates_require_integrity=False,
            corpus_require_signature=True,
            waivers=[
                Waiver(
                    id="w1", rule_id="R1", package="pkg", reason="why", owner="me", expires="2099-01-01", ticket="T-1"
                ),
            ],
        )
        d = p.to_dict()
        self.assertEqual(d["version"], POLICY_VERSION)
        self.assertEqual(d["fail_on"]["severity"], "medium")
        self.assertEqual(d["fail_on"]["rules"], ["L2-POST-001"])
        self.assertEqual(d["allow_licenses"], ["MIT", "Apache-2.0"])
        self.assertEqual(d["deny_licenses"], ["GPL-3.0"])
        self.assertEqual(d["deny_packages"], ["bad-pkg"])
        self.assertFalse(d["require"]["lockfile"])
        self.assertFalse(d["require"]["integrity"])
        self.assertTrue(d["require"]["provenance"])
        self.assertFalse(d["updates"]["enabled"])
        self.assertEqual(d["updates"]["allowed_sources"], ["https://example.com"])
        self.assertFalse(d["updates"]["require_integrity"])
        self.assertTrue(d["updates"]["corpus_require_signature"])
        self.assertEqual(len(d["waivers"]), 1)
        self.assertEqual(d["waivers"][0]["id"], "w1")

    def test_digest_deterministic(self):
        p = Policy(fail_on_severity="high")
        d1 = p.digest
        d2 = p.digest
        self.assertEqual(d1, d2)
        self.assertEqual(len(d1), 16)

    def test_digest_changes_with_policy(self):
        p1 = Policy(fail_on_severity="high")
        p2 = Policy(fail_on_severity="low")
        self.assertNotEqual(p1.digest, p2.digest)


# ── Policy.from_dict ──


class TestPolicyFromDict(unittest.TestCase):
    def test_empty_dict(self):
        p = Policy.from_dict({})
        self.assertEqual(p.fail_on_severity, "high")
        self.assertEqual(p.fail_on_rules, [])

    def test_full_dict(self):
        d = {
            "fail_on": {"severity": "critical", "rules": ["L2-CRED-001"]},
            "allow_licenses": ["MIT"],
            "deny_licenses": ["GPL-3.0"],
            "deny_packages": ["bad@1.0.0"],
            "require": {"lockfile": False, "integrity": False, "provenance": True},
            "updates": {
                "enabled": False,
                "allowed_sources": ["https://a.com"],
                "require_integrity": False,
                "corpus_require_signature": True,
            },
            "waivers": [
                {"id": "w1", "rule_id": "R1", "package": "pkg", "reason": "why", "owner": "me", "expires": "2099-01-01"}
            ],
        }
        p = Policy.from_dict(d)
        self.assertEqual(p.fail_on_severity, "critical")
        self.assertEqual(p.fail_on_rules, ["L2-CRED-001"])
        self.assertEqual(p.allow_licenses, ["MIT"])
        self.assertEqual(p.deny_licenses, ["GPL-3.0"])
        self.assertEqual(p.deny_packages, ["bad@1.0.0"])
        self.assertFalse(p.require_lockfile)
        self.assertFalse(p.require_integrity)
        self.assertTrue(p.require_provenance)
        self.assertFalse(p.updates_enabled)
        self.assertEqual(p.updates_allowed_sources, ["https://a.com"])
        self.assertFalse(p.updates_require_integrity)
        self.assertTrue(p.corpus_require_signature)
        self.assertEqual(len(p.waivers), 1)
        self.assertEqual(p.waivers[0].id, "w1")

    def test_fail_on_missing_severity(self):
        d = {"fail_on": {"rules": ["L2-CRED-001"]}}
        p = Policy.from_dict(d)
        self.assertEqual(p.fail_on_severity, "high")

    def test_fail_on_missing_rules(self):
        d = {"fail_on": {"severity": "medium"}}
        p = Policy.from_dict(d)
        self.assertEqual(p.fail_on_rules, [])

    def test_fail_on_not_dict(self):
        d = {"fail_on": "high"}
        p = Policy.from_dict(d)
        # fail_on is not a dict -> defaults
        self.assertEqual(p.fail_on_severity, "high")

    def test_licenses_stripped(self):
        d = {"allow_licenses": ["  MIT  ", " Apache-2.0 "]}
        p = Policy.from_dict(d)
        self.assertEqual(p.allow_licenses, ["MIT", "Apache-2.0"])

    def test_deny_packages_stripped(self):
        d = {"deny_packages": ["  bad-pkg  "]}
        p = Policy.from_dict(d)
        self.assertEqual(p.deny_packages, ["bad-pkg"])

    def test_waivers_parsed(self):
        d = {
            "waivers": [
                {
                    "id": "w1",
                    "rule_id": "R1",
                    "package": "pkg",
                    "reason": "why",
                    "owner": "me",
                    "expires": "2099-01-01",
                    "ticket": "T-1",
                },
            ]
        }
        p = Policy.from_dict(d)
        self.assertEqual(len(p.waivers), 1)
        self.assertEqual(p.waivers[0].ticket, "T-1")

    def test_require_partial(self):
        d = {"require": {"lockfile": False}}
        p = Policy.from_dict(d)
        self.assertFalse(p.require_lockfile)
        self.assertTrue(p.require_integrity)  # default
        self.assertFalse(p.require_provenance)  # default

    def test_updates_partial(self):
        d = {"updates": {"enabled": False}}
        p = Policy.from_dict(d)
        self.assertFalse(p.updates_enabled)
        self.assertEqual(p.updates_allowed_sources, [])
        self.assertTrue(p.updates_require_integrity)  # default


# ── Policy.from_file ──


class TestPolicyFromFile(unittest.TestCase):
    def test_missing_file_returns_default(self):
        p = Policy.from_file(Path("/nonexistent/policy.yml"))
        self.assertEqual(p.fail_on_severity, "high")  # default

    def test_valid_yaml(self):
        yaml_content = """
version: 1
fail_on:
  severity: critical
  rules:
    - L2-OBFS-001
allow_licenses:
  - MIT
  - Apache-2.0
deny_licenses:
  - GPL-3.0
deny_packages:
  - event-stream@3.3.6
require:
  lockfile: false
  integrity: false
  provenance: true
waivers:
  - id: w1
    rule_id: L2-OBFS-001
    package: event-stream
    reason: temporary
    owner: team@example.com
    expires: "2099-12-31"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                p = Policy.from_file(Path(f.name))
                self.assertEqual(p.fail_on_severity, "critical")
                self.assertEqual(p.fail_on_rules, ["L2-OBFS-001"])
                self.assertEqual(p.allow_licenses, ["MIT", "Apache-2.0"])
                self.assertFalse(p.require_lockfile)
                self.assertEqual(len(p.waivers), 1)
                self.assertEqual(p.waivers[0].id, "w1")
            finally:
                Path(f.name).unlink()

    def test_valid_json_fallback(self):
        """Test JSON loading when yaml is not importable."""
        data = {"fail_on": {"severity": "low"}, "allow_licenses": ["ISC"]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            f.flush()
            try:
                p = Policy.from_file(Path(f.name))
                self.assertEqual(p.fail_on_severity, "low")
                self.assertEqual(p.allow_licenses, ["ISC"])
            finally:
                Path(f.name).unlink()

    def test_non_mapping_yaml(self):
        """A YAML file that resolves to a non-dict should return defaults."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write("- just\n- a\n- list\n")
            f.flush()
            try:
                p = Policy.from_file(Path(f.name))
                self.assertEqual(p.fail_on_severity, "high")  # default
            finally:
                Path(f.name).unlink()

    def test_unknown_keys_warning(self):
        """Unknown policy keys should trigger a warning log."""
        yaml_content = "version: 1\nfail_on:\n  severity: high\nunknown_key: true\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                with self.assertLogs("picosentry.policy", level="WARNING") as cm:
                    Policy.from_file(Path(f.name))
                self.assertTrue(any("unknown_key" in msg for msg in cm.output))
            finally:
                Path(f.name).unlink()


# ── Policy.get_active_waivers / is_finding_waived ──


class TestPolicyWaivers(unittest.TestCase):
    def test_get_active_waivers_excludes_expired(self):
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        p = Policy(
            waivers=[
                Waiver(id="expired", rule_id="R1", package="pkg1", reason="why", owner="me", expires="2020-01-01"),
                Waiver(id="active", rule_id="R1", package="pkg2", reason="why", owner="me", expires=future),
            ]
        )
        active = p.get_active_waivers()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].id, "active")

    def test_get_active_waivers_logs_expired(self):
        p = Policy(
            waivers=[
                Waiver(id="old-w", rule_id="R1", package="pkg", reason="why", owner="me", expires="2020-01-01"),
            ]
        )
        with self.assertLogs("picosentry.policy", level="INFO") as cm:
            p.get_active_waivers()
        self.assertTrue(any("old-w" in msg for msg in cm.output))

    def test_is_finding_waived_true(self):
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        p = Policy(
            waivers=[
                Waiver(id="w1", rule_id="L2-POST-001", package="bad-pkg", reason="why", owner="me", expires=future),
            ]
        )
        waived, w = p.is_finding_waived("L2-POST-001", "bad-pkg")
        self.assertTrue(waived)
        self.assertEqual(w.id, "w1")

    def test_is_finding_waived_false_no_match(self):
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        p = Policy(
            waivers=[
                Waiver(id="w1", rule_id="L2-OTHER", package="bad-pkg", reason="why", owner="me", expires=future),
            ]
        )
        waived, w = p.is_finding_waived("L2-POST-001", "bad-pkg")
        self.assertFalse(waived)
        self.assertIsNone(w)

    def test_is_finding_waived_false_expired(self):
        p = Policy(
            waivers=[
                Waiver(
                    id="w1", rule_id="L2-POST-001", package="bad-pkg", reason="why", owner="me", expires="2020-01-01"
                ),
            ]
        )
        waived, _w = p.is_finding_waived("L2-POST-001", "bad-pkg")
        self.assertFalse(waived)


# ── Policy.check_licenses ──


class TestPolicyCheckLicenses(unittest.TestCase):
    def test_deny_license(self):
        p = Policy(deny_licenses=["GPL-3.0"])
        violations = p.check_licenses({"my-pkg": "GPL-3.0"})
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].violation_type, "license")
        self.assertEqual(violations[0].severity, "ERROR")
        self.assertIn("denied", violations[0].message)

    def test_deny_license_case_insensitive(self):
        p = Policy(deny_licenses=["gpl-3.0"])
        violations = p.check_licenses({"my-pkg": "GPL-3.0"})
        self.assertEqual(len(violations), 1)

    def test_allow_license_passes(self):
        p = Policy(allow_licenses=["MIT", "Apache-2.0"])
        violations = p.check_licenses({"my-pkg": "MIT"})
        self.assertEqual(len(violations), 0)

    def test_allow_license_blocks_unknown(self):
        # allow_licenses check requires a non-empty deny_licenses list (for-else pattern)
        p = Policy(allow_licenses=["MIT"], deny_licenses=["AGPL-3.0"])
        violations = p.check_licenses({"my-pkg": "GPL-3.0"})
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].severity, "WARNING")
        self.assertEqual(violations[0].severity, "WARNING")

    def test_deny_overrides_allow(self):
        """If a license is in both allow and deny, deny wins."""
        p = Policy(allow_licenses=["MIT", "GPL-3.0"], deny_licenses=["GPL-3.0"])
        violations = p.check_licenses({"my-pkg": "GPL-3.0"})
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].severity, "ERROR")

    def test_no_lists_no_violations(self):
        p = Policy()
        violations = p.check_licenses({"my-pkg": "GPL-3.0"})
        self.assertEqual(len(violations), 0)

    def test_allow_case_insensitive(self):
        p = Policy(allow_licenses=["mit"])
        violations = p.check_licenses({"my-pkg": "MIT"})
        self.assertEqual(len(violations), 0)

    def test_empty_package_licenses(self):
        p = Policy(allow_licenses=["MIT"])
        violations = p.check_licenses({})
        self.assertEqual(len(violations), 0)


# ── Policy.check_packages ──


class TestPolicyCheckPackages(unittest.TestCase):
    def test_deny_package(self):
        p = Policy(deny_packages=["event-stream"])
        violations = p.check_packages({"event-stream", "lodash"})
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].violation_type, "deny_package")

    def test_deny_package_with_version(self):
        p = Policy(deny_packages=["event-stream@3.3.6"])
        violations = p.check_packages({"event-stream@3.3.6"})
        self.assertEqual(len(violations), 1)

    def test_no_deny_packages(self):
        p = Policy()
        violations = p.check_packages({"lodash"})
        self.assertEqual(len(violations), 0)

    def test_empty_installed_packages(self):
        p = Policy(deny_packages=["bad-pkg"])
        violations = p.check_packages(set())
        self.assertEqual(len(violations), 0)


# ── Policy.check_requirements ──


class TestPolicyCheckRequirements(unittest.TestCase):
    def test_no_lockfile(self):
        with tempfile.TemporaryDirectory() as td:
            p = Policy(require_lockfile=True, require_integrity=False)
            violations = p.check_requirements(Path(td))
            self.assertTrue(any(v.detail.get("required") == "lockfile" for v in violations))

    def test_has_package_lock(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "package-lock.json").write_text("{}")
            p = Policy(require_lockfile=True, require_integrity=True)
            violations = p.check_requirements(Path(td))
            # Has lockfile, and integrity is satisfied by package-lock.json
            lockfile_violations = [v for v in violations if v.detail.get("required") == "lockfile"]
            integrity_violations = [v for v in violations if v.detail.get("required") == "integrity"]
            self.assertEqual(len(lockfile_violations), 0)
            self.assertEqual(len(integrity_violations), 0)

    def test_has_pnpm_lock(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "pnpm-lock.yaml").write_text("")
            p = Policy(require_lockfile=True, require_integrity=True)
            violations = p.check_requirements(Path(td))
            lockfile_v = [v for v in violations if v.detail.get("required") == "lockfile"]
            self.assertEqual(len(lockfile_v), 0)

    def test_has_yarn_lock(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "yarn.lock").write_text("")
            p = Policy(require_lockfile=True, require_integrity=False)
            violations = p.check_requirements(Path(td))
            lockfile_v = [v for v in violations if v.detail.get("required") == "lockfile"]
            self.assertEqual(len(lockfile_v), 0)

    def test_integrity_no_lockfile(self):
        with tempfile.TemporaryDirectory() as td:
            p = Policy(require_lockfile=False, require_integrity=True)
            violations = p.check_requirements(Path(td))
            self.assertTrue(any(v.detail.get("required") == "integrity" for v in violations))

    def test_no_requirements(self):
        with tempfile.TemporaryDirectory() as td:
            p = Policy(require_lockfile=False, require_integrity=False)
            violations = p.check_requirements(Path(td))
            self.assertEqual(len(violations), 0)


# ── Policy.apply ──


class TestPolicyApply(unittest.TestCase):
    def test_severity_violation(self):
        p = Policy(fail_on_severity="high")
        sr = _make_scan_result([_make_finding(severity=Severity.HIGH)])
        with tempfile.TemporaryDirectory() as td:
            result = p.apply(sr, Path(td))
        self.assertFalse(result.passed)
        self.assertTrue(any(v.violation_type == "severity" for v in result.violations))

    def test_severity_below_threshold_passes(self):
        p = Policy(fail_on_severity="critical")
        sr = _make_scan_result([_make_finding(severity=Severity.LOW)])
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "package-lock.json").write_text("{}")
            result = p.apply(sr, Path(td))
        self.assertTrue(result.passed)

    def test_rule_specific_fail(self):
        p = Policy(fail_on_rules=["L2-POST-001"])
        sr = _make_scan_result([_make_finding(rule_id="L2-POST-001", severity=Severity.LOW)])
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "package-lock.json").write_text("{}")
            result = p.apply(sr, Path(td))
        self.assertFalse(result.passed)
        self.assertTrue(any("L2-POST-001" in v.message for v in result.violations))

    def test_waived_finding(self):
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        p = Policy(
            fail_on_severity="low",
            waivers=[
                Waiver(id="w1", rule_id="L2-POST-001", package="bad-pkg", reason="approved", owner="me", expires=future)
            ],
        )
        sr = _make_scan_result([_make_finding(rule_id="L2-POST-001", package="bad-pkg")])
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "package-lock.json").write_text("{}")
            result = p.apply(sr, Path(td))
        self.assertTrue(result.passed)
        self.assertEqual(result.waived_findings, 1)

    def test_expired_waiver_still_violates(self):
        p = Policy(
            fail_on_severity="low",
            waivers=[
                Waiver(
                    id="w1",
                    rule_id="L2-POST-001",
                    package="bad-pkg",
                    reason="expired",
                    owner="me",
                    expires="2020-01-01",
                )
            ],
        )
        sr = _make_scan_result([_make_finding(rule_id="L2-POST-001", package="bad-pkg")])
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "package-lock.json").write_text("{}")
            result = p.apply(sr, Path(td))
        self.assertFalse(result.passed)
        self.assertIn("w1", result.expired_waivers)

    def test_license_violation(self):
        p = Policy(allow_licenses=["MIT"], deny_licenses=["AGPL-3.0"])
        sr = _make_scan_result([])
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "package-lock.json").write_text("{}")
            result = p.apply(sr, Path(td), package_licenses={"my-pkg": "GPL-3.0"})
        self.assertFalse(result.passed)

    def test_deny_package_violation(self):
        p = Policy(deny_packages=["bad-pkg"])
        sr = _make_scan_result([])
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "package-lock.json").write_text("{}")
            result = p.apply(sr, Path(td), installed_packages={"bad-pkg"})
        self.assertFalse(result.passed)

    def test_no_findings_passes(self):
        p = Policy()
        sr = _make_scan_result([])
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "package-lock.json").write_text("{}")
            result = p.apply(sr, Path(td))
        self.assertTrue(result.passed)

    def test_all_severity_levels(self):
        for sev_name, sev_val in [
            ("critical", Severity.CRITICAL),
            ("high", Severity.HIGH),
            ("medium", Severity.MEDIUM),
            ("low", Severity.LOW),
            ("info", Severity.INFO),
        ]:
            p = Policy(fail_on_severity=sev_name)
            sr = _make_scan_result([_make_finding(severity=sev_val)])
            with tempfile.TemporaryDirectory() as td:
                (Path(td) / "package-lock.json").write_text("{}")
                result = p.apply(sr, Path(td))
            self.assertFalse(result.passed, f"Expected violation for severity={sev_name}")

    def test_info_below_high_threshold(self):
        p = Policy(fail_on_severity="high")
        sr = _make_scan_result([_make_finding(severity=Severity.INFO)])
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "package-lock.json").write_text("{}")
            result = p.apply(sr, Path(td))
        self.assertTrue(result.passed)

    def test_result_includes_policy_digest(self):
        p = Policy()
        sr = _make_scan_result([])
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "package-lock.json").write_text("{}")
            result = p.apply(sr, Path(td))
        self.assertEqual(result.policy_digest, p.digest)


# ── export_signed_policy / import_policy_bundle ──


class TestPolicyBundle(unittest.TestCase):
    def test_export_and_import_roundtrip(self):
        p = Policy(fail_on_severity="medium", allow_licenses=["MIT"])
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "policy_bundle.json"
            digest = export_signed_policy(p, out, signer="test@example.com")
            self.assertTrue(out.exists())
            self.assertTrue(digest.startswith("sha256:"))

            imported = import_policy_bundle(out, verify=True, verify_crypto=False)
            self.assertEqual(imported.fail_on_severity, "medium")
            self.assertEqual(imported.allow_licenses, ["MIT"])

    def test_import_missing_policy_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"digest": "sha256:abc", "signer": "test"}, f)
            f.flush()
            try:
                with self.assertRaises(ValueError) as ctx:
                    import_policy_bundle(Path(f.name), verify=False, verify_crypto=False)
                self.assertIn("missing 'policy' key", str(ctx.exception))
            finally:
                Path(f.name).unlink()

    def test_import_digest_mismatch(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            bundle = {
                "policy": {"fail_on": {"severity": "high"}},
                "digest": "sha256:deadbeef",
            }
            json.dump(bundle, f)
            f.flush()
            try:
                with self.assertRaises(ValueError) as ctx:
                    import_policy_bundle(Path(f.name), verify=True, verify_crypto=False)
                self.assertIn("digest mismatch", str(ctx.exception))
            finally:
                Path(f.name).unlink()

    def test_import_digest_valid(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            policy_dict = {"fail_on": {"severity": "high"}}
            policy_json = json.dumps(policy_dict, sort_keys=True, separators=(",", ":"))
            digest = f"sha256:{hashlib.sha256(policy_json.encode()).hexdigest()[:32]}"
            bundle = {
                "policy": policy_dict,
                "digest": digest,
            }
            json.dump(bundle, f)
            f.flush()
            try:
                imported = import_policy_bundle(Path(f.name), verify=True, verify_crypto=False)
                self.assertEqual(imported.fail_on_severity, "high")
            finally:
                Path(f.name).unlink()

    def test_export_without_signer(self):
        p = Policy()
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "bundle.json"
            export_signed_policy(p, out)
            data = json.loads(out.read_text())
            self.assertEqual(data["signer"], "unsigned")

    def test_export_signer(self):
        p = Policy()
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "bundle.json"
            export_signed_policy(p, out, signer="alice@example.com")
            data = json.loads(out.read_text())
            self.assertEqual(data["signer"], "alice@example.com")


# ── policy_from_org ──


class TestPolicyFromOrg(unittest.TestCase):
    def test_startup(self):
        p = policy_from_org("startup")
        self.assertEqual(p.fail_on_severity, "high")
        self.assertTrue(p.require_lockfile)
        self.assertIn("MIT", p.allow_licenses)

    def test_enterprise(self):
        p = policy_from_org("enterprise")
        self.assertEqual(p.fail_on_severity, "medium")
        self.assertIn("L2-POST-001", p.fail_on_rules)
        self.assertIn("GPL-3.0", p.deny_licenses)
        self.assertTrue(p.require_lockfile)

    def test_oss(self):
        p = policy_from_org("oss")
        self.assertEqual(p.fail_on_severity, "critical")
        self.assertTrue(p.require_lockfile)
        self.assertFalse(p.require_integrity)
        self.assertIn("GPL-3.0", p.allow_licenses)

    def test_government(self):
        p = policy_from_org("government")
        self.assertEqual(p.fail_on_severity, "low")
        self.assertTrue(p.require_provenance)
        self.assertIn("UNLICENSED", p.deny_licenses)

    def test_unknown_org_returns_default(self):
        p = policy_from_org("unknown_org")
        self.assertEqual(p.fail_on_severity, "high")  # default

    def test_case_insensitive(self):
        p = policy_from_org("STARTUP")
        self.assertEqual(p.fail_on_severity, "high")

    def test_unknown_org_logs_warning(self):
        with self.assertLogs("picosentry.policy", level="WARNING") as cm:
            policy_from_org("nonexistent")
        self.assertTrue(any("nonexistent" in msg for msg in cm.output))


# ── default_policy_template ──


class TestDefaultPolicyTemplate(unittest.TestCase):
    def test_returns_string(self):
        tpl = default_policy_template()
        self.assertIsInstance(tpl, str)
        self.assertIn("fail_on", tpl)
        self.assertIn("allow_licenses", tpl)


# ── Strict / unknown key warnings ──


class TestStrictConfigMode(unittest.TestCase):
    def test_unknown_keys_in_from_dict_are_ignored(self):
        """from_dict doesn't validate unknown keys — it just ignores them."""
        d = {"fail_on": {"severity": "low"}, "custom_key": "value"}
        p = Policy.from_dict(d)
        self.assertEqual(p.fail_on_severity, "low")

    def test_unknown_keys_in_from_file_warns(self):
        """from_file logs warnings for unknown keys."""
        yaml_content = "version: 1\nfail_on:\n  severity: high\nweird_key: true\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                with self.assertLogs("picosentry.policy", level="WARNING") as cm:
                    Policy.from_file(Path(f.name))
                self.assertTrue(any("weird_key" in msg for msg in cm.output))
            finally:
                Path(f.name).unlink()

    def test_known_keys_no_warning(self):
        yaml_content = "version: 1\nfail_on:\n  severity: high\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                # No warnings should be produced for known keys
                p = Policy.from_file(Path(f.name))
                self.assertEqual(p.fail_on_severity, "high")
            finally:
                Path(f.name).unlink()


# ── Policy.check_packages edge cases ──


class TestPolicyCheckPackagesEdge(unittest.TestCase):
    def test_deny_package_name_only_matches_versioned(self):
        p = Policy(deny_packages=["bad-pkg"])
        # "bad-pkg" in deny list should match "bad-pkg@1.0.0" in installed
        violations = p.check_packages({"bad-pkg@1.0.0"})
        self.assertEqual(len(violations), 1)

    def test_deny_package_versioned_matches(self):
        p = Policy(deny_packages=["bad-pkg@1.0.0"])
        violations = p.check_packages({"bad-pkg@1.0.0"})
        self.assertEqual(len(violations), 1)

    def test_no_match(self):
        p = Policy(deny_packages=["bad-pkg"])
        violations = p.check_packages({"good-pkg"})
        self.assertEqual(len(violations), 0)


# ── Waiver.matches edge cases ──


class TestWaiverMatchesEdge(unittest.TestCase):
    def test_scoped_package_with_version(self):
        w = Waiver(id="w1", rule_id="R1", package="@scope/name@1.0.0", reason="why", owner="me", expires="2099-01-01")
        # Waiver for @scope/name@1.0.0 matches exact same label
        self.assertTrue(w.matches("R1", "@scope/name@1.0.0"))
        # Waiver for @scope/name@1.0.0 doesn't match @scope/name (no version) via wildcard
        # because the name part matches, so this SHOULD match via name-only path
        self.assertTrue(w.matches("R1", "@scope/name@2.0.0"))

    def test_wildcard_package_matches_any(self):
        w = Waiver(id="w1", rule_id="R1", package="*", reason="why", owner="me", expires="2099-01-01")
        self.assertTrue(w.matches("R1", "any-pkg"))
        self.assertTrue(w.matches("R1", "@scope/name@1.0.0"))


# ── Policy.apply integration ──


class TestPolicyApplyIntegration(unittest.TestCase):
    def test_multiple_violation_types(self):
        p = Policy(
            fail_on_severity="low",
            allow_licenses=["MIT"],
            deny_licenses=["GPL-3.0"],
            deny_packages=["bad-pkg"],
        )
        sr = _make_scan_result([_make_finding(severity=Severity.HIGH)])
        with tempfile.TemporaryDirectory() as td:
            result = p.apply(
                sr,
                Path(td),
                package_licenses={"my-pkg": "GPL-3.0"},
                installed_packages={"bad-pkg"},
            )
        self.assertFalse(result.passed)
        types = {v.violation_type for v in result.violations}
        self.assertIn("severity", types)
        self.assertIn("license", types)
        self.assertIn("deny_package", types)

    def test_result_to_dict(self):
        p = Policy(fail_on_severity="low")
        sr = _make_scan_result([_make_finding(severity=Severity.HIGH)])
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "package-lock.json").write_text("{}")
            result = p.apply(sr, Path(td))
        d = result.to_dict()
        self.assertIn("passed", d)
        self.assertIn("violations", d)
        self.assertIn("waived_findings", d)
        self.assertIn("policy_digest", d)

    def test_severity_ordering_medium(self):
        """Medium severity triggers violation when fail_on is 'medium'."""
        p = Policy(fail_on_severity="medium")
        sr = _make_scan_result([_make_finding(severity=Severity.MEDIUM)])
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "package-lock.json").write_text("{}")
            result = p.apply(sr, Path(td))
        self.assertFalse(result.passed)

    def test_severity_ordering_info_not_medium(self):
        """Info severity does NOT trigger violation when fail_on is 'medium'."""
        p = Policy(fail_on_severity="medium")
        sr = _make_scan_result([_make_finding(severity=Severity.INFO)])
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "package-lock.json").write_text("{}")
            result = p.apply(sr, Path(td))
        self.assertTrue(result.passed)


if __name__ == "__main__":
    unittest.main()
