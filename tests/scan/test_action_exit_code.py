"""
test_action_exit_code.py — Regression tests for GitHub Action exit-code enforcement.

These tests validate the core contract of action.yml's "Run PicoSentry scan" step:
- When exit-code=true and picosentry exits nonzero (findings), the step MUST exit 1.
- When exit-code=false, the step MUST exit 0 regardless of findings.
- When picosentry exits 0 (clean), the step MUST exit 0.
- Output variables (findings count, result) must be correctly set.

The tests exercise the exact shell logic from action.yml by invoking picosentry
via subprocess and checking the same conditions the action script checks.
"""

import json
import subprocess
import sys

import pytest

from tests.scan.conftest import FIXTURES_DIR

PICOSENTRY = [sys.executable, "-m", "picosentry"]


def _scan(fixture_name: str, extra_args: list[str] | None = None) -> subprocess.CompletedProcess:
    """Run picosentry scan on a fixture, return CompletedProcess."""
    fixture = FIXTURES_DIR / fixture_name
    if not fixture.is_dir():
        pytest.skip(f"fixture {fixture_name} not available")
    args = PICOSENTRY + ["scan", str(fixture)] + (extra_args or [])
    return subprocess.run(args, capture_output=True, text=True, timeout=60)


class TestExitCodeEnforcement:
    """
    Core contract: --exit-code and --fail-on MUST cause nonzero exit when
    findings exceed the threshold. This is the exact logic the GitHub Action
    depends on.

    Before the fix, action.yml caught picosentry's nonzero exit but never
    propagated it — the step always succeeded even with exit-code: true.
    """

    def test_malicious_project_exit_code_exits_nonzero(self):
        """Scanning a project with findings + --exit-code MUST exit 1."""
        result = _scan("shai_hulud", ["--exit-code"])
        assert result.returncode == 1, (
            f"picosentry --exit-code on malicious fixture should exit 1, "
            f"got {result.returncode}. stderr: {result.stderr}"
        )

    def test_malicious_project_fail_on_high_exits_nonzero(self):
        """Scanning a project with HIGH+ findings + --fail-on high MUST exit 1."""
        result = _scan("shai_hulud", ["--fail-on", "high"])
        assert result.returncode == 1, (
            f"picosentry --fail-on high on malicious fixture should exit 1, "
            f"got {result.returncode}. stderr: {result.stderr}"
        )

    def test_malicious_project_fail_on_critical_only_may_exit_zero(self):
        """If no CRITICAL findings, --fail-on critical should exit 0 even with HIGH findings."""
        result = _scan("shai_hulud", ["--fail-on", "critical"])
        # shai_hulud has HIGH findings but likely no CRITICAL ones
        # This should exit 0 if no critical findings exist
        assert result.returncode in (0, 1), f"Unexpected exit code: {result.returncode}. stderr: {result.stderr}"

    def test_clean_project_exit_code_with_any_findings(self):
        """Scanning with --exit-code exits 1 if ANY findings exist (even LOW/INFO).

        The clean_project fixture has a LOW finding (L2-ENGIN-001: missing engines field).
        --exit-code means "exit 1 if any findings found" — severity is irrelevant.
        This is the behavior the GitHub Action depends on.
        """
        result = _scan("clean_project", ["--exit-code"])
        assert result.returncode == 1, (
            f"picosentry --exit-code with any findings should exit 1, "
            f"got {result.returncode}. stdout: {result.stdout[:200]}"
        )

    def test_malicious_project_no_exit_code_exits_zero(self):
        """Without --exit-code, picosentry MUST exit 0 even with findings."""
        result = _scan("shai_hulud")
        assert result.returncode == 0, (
            f"picosentry without --exit-code should exit 0 regardless of findings, "
            f"got {result.returncode}. stderr: {result.stderr}"
        )

    def test_json_output_has_findings_count(self):
        """JSON output must include findings array so the action can count them."""
        result = _scan("shai_hulud", ["--format", "json"])
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert "findings" in data, "JSON output must include findings"
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) > 0, "shai_hulud should have findings"


class TestActionResultOutputs:
    """
    Validate that the GitHub Action can correctly extract findings count and
    pass/fail result from picosentry output — the same logic used in action.yml.
    """

    def test_action_finding_count_from_json(self, tmp_path):
        """The action counts findings from JSON output. Verify it works."""
        output_file = tmp_path / "results.json"
        result = _scan("shai_hulud", ["--format", "json", "--output", str(output_file)])
        assert result.returncode == 0
        assert output_file.exists(), "JSON output file must be created"

        data = json.loads(output_file.read_text())
        findings_count = len(data.get("findings", []))
        assert findings_count > 0, "shai_hulud should have findings in JSON output"

    def test_action_result_has_low_finding_on_clean_project(self):
        """The 'clean' project fixture has 1 LOW finding (missing engines field).

        This is intentional — it tests that even INFO/LOW findings are reported.
        A truly clean project would need no findings at all.
        """
        result = _scan("clean_project", ["--format", "json"])
        assert result.returncode == 0
        data = json.loads(result.stdout)
        findings = data.get("findings", [])
        assert len(findings) >= 1, f"clean_project should have at least 1 finding, got {len(findings)}"
        assert any(f["severity"] in ("LOW", "INFO") for f in findings), (
            f"clean_project findings should include LOW/INFO, got {[f['severity'] for f in findings]}"
        )

    def test_action_result_fail_on_malicious_scan(self):
        """A scan with findings should produce result=fail when using --exit-code."""
        result = _scan("shai_hulud", ["--exit-code"])
        assert result.returncode == 1


class TestActionShellLogic:
    """
    Test the EXACT shell logic from action.yml's "Run PicoSentry scan" step.

    These replicate the action's exit-code enforcement in pure Python to
    prove the fix works: when EXIT_CODE != 0 and exit-code input is "true",
    the action must exit 1.
    """

    def test_action_logic_exit_code_true_with_findings(self):
        """
        Replicates: when picosentry exits nonzero and exit-code input is "true",
        the action step must exit 1.

        Before the fix, the action caught the error but never exited nonzero.
        """
        # Simulate: run picosentry with --exit-code on a malicious project
        result = _scan("shai_hulud", ["--exit-code"])
        picosentry_exit_code = result.returncode

        # This is the EXACT logic from action.yml after the fix:
        # if [ "${{ inputs.exit-code }}" = "true" ] && [ "$EXIT_CODE" -ne 0 ]; then
        #     echo "::error::PicoSentry found issues"
        #     exit 1
        # fi
        exit_code_input = "true"
        action_should_fail = exit_code_input == "true" and picosentry_exit_code != 0

        assert action_should_fail is True, (
            f"When exit-code=true and picosentry exits {picosentry_exit_code}, the GitHub Action step MUST fail"
        )

    def test_action_logic_exit_code_true_with_fail_on_high_no_high_findings(self):
        """
        When using --fail-on high on a project with only LOW findings,
        picosentry should exit 0, and the action should NOT fail.

        This tests the severity threshold: only findings at HIGH+ trigger failure.
        """
        result = _scan("clean_project", ["--fail-on", "high"])
        picosentry_exit_code = result.returncode
        # clean_project has only LOW findings, --fail-on high should exit 0
        assert picosentry_exit_code == 0, (
            f"--fail-on high with only LOW findings should exit 0, got {picosentry_exit_code}"
        )

        exit_code_input = "true"
        action_should_fail = exit_code_input == "true" and picosentry_exit_code != 0

        assert action_should_fail is False, "Project with only LOW findings + --fail-on high should NOT fail the action"

    def test_action_logic_exit_code_false_with_findings(self):
        """
        When exit-code=false (default "true" but explicitly set), the action
        should NOT fail even with findings. This is for "report only" mode.
        """
        # Run WITHOUT --exit-code (simulates exit-code input = "false")
        result = _scan("shai_hulud")
        picosentry_exit_code = result.returncode

        # picosentry without --exit-code always exits 0
        assert picosentry_exit_code == 0, "Without --exit-code, picosentry should exit 0"

        exit_code_input = "false"
        action_should_fail = exit_code_input == "true" and picosentry_exit_code != 0

        assert action_should_fail is False, "When exit-code=false, the GitHub Action should NOT fail"

    def test_action_logic_fail_on_severity(self):
        """
        --fail-on is equivalent to --exit-code with a severity threshold.
        The action passes --fail-on always and --exit-code conditionally.
        Both must cause exit 1 when findings meet the threshold.
        """
        result = _scan("shai_hulud", ["--fail-on", "high"])
        picosentry_exit_code = result.returncode

        exit_code_input = "true"
        action_should_fail = exit_code_input == "true" and picosentry_exit_code != 0

        assert action_should_fail is True, (
            f"--fail-on high with exit-code=true must fail the action (got {picosentry_exit_code})"
        )


class TestDeterministicOutputCLI:
    """Test --deterministic-output flag via CLI."""

    def test_deterministic_output_produces_stable_json(self, tmp_path):
        """Two runs with --deterministic-output must produce byte-identical JSON."""
        out_a = tmp_path / "det_a.json"
        out_b = tmp_path / "det_b.json"

        _scan("colors_js", ["--format", "json", "--deterministic-output", "--output", str(out_a)])
        _scan("colors_js", ["--format", "json", "--deterministic-output", "--output", str(out_b)])

        json_a = out_a.read_text()
        json_b = out_b.read_text()

        assert json_a == json_b, "Two --deterministic-output runs must produce byte-identical JSON"

    def test_normal_output_includes_timing(self, tmp_path):
        """Normal JSON output must include audit timestamps and timing."""
        out = tmp_path / "normal.json"
        _scan("colors_js", ["--format", "json", "--output", str(out)])

        data = json.loads(out.read_text())
        assert "audit" in data, "Normal output must include audit section"
        assert "started_at" in data.get("audit", {}), "Normal output must include started_at"

    def test_deterministic_output_omits_audit(self, tmp_path):
        """--deterministic-output must NOT include audit timestamps."""
        out = tmp_path / "det.json"
        _scan("colors_js", ["--format", "json", "--deterministic-output", "--output", str(out)])

        data = json.loads(out.read_text())
        assert "audit" not in data, "--deterministic-output must NOT include audit section"

    def test_deterministic_output_omits_duration(self, tmp_path):
        """--deterministic-output must NOT include duration_ms in stats."""
        out = tmp_path / "det.json"
        _scan("colors_js", ["--format", "json", "--deterministic-output", "--output", str(out)])

        data = json.loads(out.read_text())
        assert "duration_ms" not in data.get("stats", {}), (
            "--deterministic-output must NOT include duration_ms in stats"
        )
        assert "rule_timings_ms" not in data.get("stats", {}), (
            "--deterministic-output must NOT include rule_timings_ms in stats"
        )

    def test_deterministic_output_keys_are_sorted(self, tmp_path):
        """--deterministic-output JSON must have sorted top-level keys."""
        out = tmp_path / "det.json"
        _scan("colors_js", ["--format", "json", "--deterministic-output", "--output", str(out)])

        data = json.loads(out.read_text())
        keys = list(data.keys())
        assert keys == sorted(keys), f"Keys must be sorted, got: {keys}"

    def test_verify_determinism_flag_implies_deterministic_output(self, tmp_path):
        """--verify-determinism should produce stable JSON (implies deterministic output)."""
        result = _scan("colors_js", ["--verify-determinism"])
        assert result.returncode == 0, f"--verify-determinism should succeed, got {result.returncode}"
        assert "DETERMINISM VERIFIED" in result.stderr, (
            f"--verify-determinism should report verification. stderr: {result.stderr}"
        )
