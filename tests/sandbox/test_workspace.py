"""Tests for workspace / multi-project scanning."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from picosentry.sandbox.l3.models import SandboxResult
from picosentry.sandbox.l4.models import AnalysisResult, BehavioralProfile, BehavioralVerdict
from picosentry.sandbox.models import Finding, Severity, Verdict
from picosentry.sandbox.workspace import (
    PROJECT_MARKERS,
    SKIP_DIRS,
    ProjectInfo,
    WorkspaceResult,
    _default_sandbox_commands,
    discover_projects,
    scan_workspace,
    scan_workspace_to_json,
)

# ── ProjectInfo ──────────────────────────────────────────────────────────────


class TestProjectInfo:
    def test_defaults(self):
        pi = ProjectInfo(path=Path("/tmp/myproj"), project_type="node")
        assert pi.name == "myproj"
        assert pi.version == ""

    def test_custom_name_version(self):
        pi = ProjectInfo(path=Path("/tmp/proj"), project_type="python", name="mypkg", version="1.2.3")
        assert pi.name == "mypkg"
        assert pi.version == "1.2.3"

    def test_to_dict(self):
        pi = ProjectInfo(path=Path("/tmp/proj"), project_type="mixed", name="x", version="2.0")
        d = pi.to_dict()
        assert d["path"] == "/tmp/proj"
        assert d["type"] == "mixed"
        assert d["name"] == "x"
        assert d["version"] == "2.0"


# ── WorkspaceResult ───────────────────────────────────────────────────────────


class TestWorkspaceResult:
    def test_initial_state(self):
        wr = WorkspaceResult()
        assert wr.total_projects == 0
        assert wr.scanned_projects == 0
        assert wr.failed_projects == 0
        assert wr.total_findings == 0
        assert wr.errors == []

    def test_to_dict(self):
        wr = WorkspaceResult()
        wr.total_projects = 3
        wr.scanned_projects = 2
        wr.failed_projects = 1
        wr.total_findings = 5
        wr.duration_ms = 100
        wr.errors = ["err1"]
        d = wr.to_dict()
        assert d["total_projects"] == 3
        assert d["scanned_projects"] == 2
        assert d["failed_projects"] == 1
        assert d["total_findings"] == 5
        assert d["duration_ms"] == 100
        assert d["errors"] == ["err1"]

    def test_to_dict_includes_projects(self):
        wr = WorkspaceResult()
        pi = ProjectInfo(path=Path("/tmp/p"), project_type="node", name="p")
        wr.projects["/tmp/p"] = pi
        d = wr.to_dict()
        assert "/tmp/p" in d["projects"]


# ── discover_projects ─────────────────────────────────────────────────────────


class TestDiscoverProjects:
    def test_empty_dir(self, tmp_path):
        result = discover_projects(tmp_path)
        assert result == []

    def test_not_a_dir(self):
        result = discover_projects(Path("/nonexistent/path/abc123"))
        assert result == []

    def test_node_project(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "test-proj", "version": "1.0.0"}')
        projects = discover_projects(tmp_path)
        assert len(projects) == 1
        assert projects[0].project_type == "node"
        assert projects[0].name == "test-proj"
        assert projects[0].version == "1.0.0"

    def test_python_project_requirements(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask\n")
        projects = discover_projects(tmp_path)
        assert len(projects) == 1
        assert projects[0].project_type == "python"

    def test_python_project_pyproject(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
        projects = discover_projects(tmp_path)
        assert len(projects) == 1
        assert projects[0].project_type == "python"

    def test_python_project_setup_py(self, tmp_path):
        (tmp_path / "setup.py").write_text("from setuptools import setup; setup()\n")
        projects = discover_projects(tmp_path)
        assert len(projects) == 1
        assert projects[0].project_type == "python"

    def test_python_project_pipfile(self, tmp_path):
        (tmp_path / "Pipfile").write_text("[packages]\n")
        projects = discover_projects(tmp_path)
        assert len(projects) == 1
        assert projects[0].project_type == "python"

    def test_python_project_poetry_lock(self, tmp_path):
        (tmp_path / "poetry.lock").write_text("[[package]]\n")
        projects = discover_projects(tmp_path)
        assert len(projects) == 1
        assert projects[0].project_type == "python"

    def test_mixed_project(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "mixed-proj"}')
        (tmp_path / "requirements.txt").write_text("flask\n")
        projects = discover_projects(tmp_path)
        assert len(projects) == 1
        assert projects[0].project_type == "mixed"

    def test_nested_projects(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "root-proj"}')
        sub = tmp_path / "packages" / "lib"
        sub.mkdir(parents=True)
        (sub / "pyproject.toml").write_text("[project]\nname='lib'\n")
        projects = discover_projects(tmp_path)
        assert len(projects) == 2
        types = {p.project_type for p in projects}
        assert "node" in types
        assert "python" in types

    def test_skip_dirs_ignored(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "root"}')
        node_modules = tmp_path / "node_modules" / "dep"
        node_modules.mkdir(parents=True)
        (node_modules / "package.json").write_text('{"name": "dep"}')
        projects = discover_projects(tmp_path)
        names = [p.name for p in projects]
        assert "dep" not in names

    def test_skip_dirs_git_venv(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "root"}')
        for skip in [".git", ".venv", "__pycache__", ".tox"]:
            d = tmp_path / skip / "sub"
            d.mkdir(parents=True)
            (d / "package.json").write_text('{"name": "skipped"}')
        projects = discover_projects(tmp_path)
        names = [p.name for p in projects]
        assert "skipped" not in names

    def test_max_depth(self, tmp_path):
        deep = tmp_path
        for i in range(10):
            deep = deep / f"level{i}"
        deep.mkdir(parents=True)
        (deep / "package.json").write_text('{"name": "deep"}')
        projects = discover_projects(tmp_path, max_depth=3)
        assert len(projects) == 0

    def test_dedup_same_dir(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "uni"}')
        (tmp_path / "pyproject.toml").write_text("[project]\n")
        projects = discover_projects(tmp_path)
        assert len(projects) == 1
        assert projects[0].project_type == "mixed"

    def test_permission_error_skipped(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "root"}')
        no_access = tmp_path / "noperm"
        no_access.mkdir()
        try:
            os.chmod(no_access, 0o000)
            projects = discover_projects(tmp_path)
            assert len(projects) >= 1
        finally:
            os.chmod(no_access, 0o755)

    def test_package_json_name_fallback(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        projects = discover_projects(tmp_path)
        assert len(projects) == 1
        assert projects[0].name == tmp_path.name

    def test_project_markers_constant(self):
        assert "package.json" in PROJECT_MARKERS
        assert "pyproject.toml" in PROJECT_MARKERS
        assert "requirements.txt" in PROJECT_MARKERS
        assert "setup.py" in PROJECT_MARKERS
        assert "Pipfile" in PROJECT_MARKERS
        assert "poetry.lock" in PROJECT_MARKERS
        assert "pnpm-workspace.yaml" in PROJECT_MARKERS
        assert "lerna.json" in PROJECT_MARKERS
        assert "nx.json" in PROJECT_MARKERS
        assert "turbo.json" in PROJECT_MARKERS

    def test_skip_dirs_constant(self):
        assert "node_modules" in SKIP_DIRS
        assert ".git" in SKIP_DIRS
        assert "__pycache__" in SKIP_DIRS
        assert ".venv" in SKIP_DIRS
        assert ".tox" in SKIP_DIRS


# ── _default_sandbox_commands ─────────────────────────────────────────────────


class TestDefaultSandboxCommands:
    def test_node_commands(self):
        pi = ProjectInfo(path=Path("/tmp/p"), project_type="node")
        cmds = _default_sandbox_commands(pi)
        assert len(cmds) == 2
        assert cmds[0][0] == "npm"
        assert cmds[1][0] == "npm"

    def test_python_commands(self):
        pi = ProjectInfo(path=Path("/tmp/p"), project_type="python")
        cmds = _default_sandbox_commands(pi)
        assert len(cmds) == 1
        assert cmds[0][0] == "pip"

    def test_mixed_commands(self):
        pi = ProjectInfo(path=Path("/tmp/p"), project_type="mixed")
        cmds = _default_sandbox_commands(pi)
        assert len(cmds) == 2  # npm + pip

    def test_unknown_returns_empty(self):
        pi = ProjectInfo(path=Path("/tmp/p"), project_type="unknown")
        cmds = _default_sandbox_commands(pi)
        assert cmds == []


# ── scan_workspace (mocked) ───────────────────────────────────────────────────


def _make_sandbox_result(verdict=Verdict.ALLOW, stdout="ok"):
    return SandboxResult(
        command=["echo", "test"],
        overall_verdict=verdict,
        exit_code=0,
        events=[],
        policy_name="test",
        stdout=stdout,
        stderr="",
    )


def _make_analysis(findings=None, verdict=BehavioralVerdict.CLEAN):
    return AnalysisResult(
        target="proj",
        findings=findings or [],
        overall_verdict=verdict,
    )


class TestScanWorkspace:
    def _make_project(self, tmp_path, name="proj", ptype="node"):
        proj = tmp_path / name
        proj.mkdir()
        if ptype == "node":
            (proj / "package.json").write_text('{"name":"proj","scripts":{"test":"echo test"}}')
        else:
            (proj / "requirements.txt").write_text("flask\n")
        return proj

    @patch("picosentry.sandbox.workspace.sandbox_run")
    @patch("picosentry.sandbox.workspace.profile_from_sandbox_result")
    @patch("picosentry.sandbox.workspace.create_default_engine")
    def test_scan_single_project(self, mock_engine_fn, mock_profile, mock_sandbox, tmp_path):
        self._make_project(tmp_path)
        mock_sandbox.return_value = _make_sandbox_result()
        mock_profile.return_value = BehavioralProfile(
            package="proj", entrypoint="echo", total_runtime_ms=10, exit_code=0
        )
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = _make_analysis()
        mock_engine_fn.return_value = mock_engine

        result = scan_workspace(tmp_path)
        assert result.total_projects == 1
        assert result.scanned_projects == 1
        assert result.failed_projects == 0
        assert result.total_findings == 0

    @patch("picosentry.sandbox.workspace.sandbox_run")
    @patch("picosentry.sandbox.workspace.profile_from_sandbox_result")
    @patch("picosentry.sandbox.workspace.create_default_engine")
    def test_scan_with_findings(self, mock_engine_fn, mock_profile, mock_sandbox, tmp_path):
        self._make_project(tmp_path)
        mock_sandbox.return_value = _make_sandbox_result(verdict=Verdict.DENY, stdout="evil")
        mock_profile.return_value = BehavioralProfile(
            package="proj", entrypoint="echo", total_runtime_ms=10, exit_code=0
        )
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = _make_analysis(
            findings=[Finding(rule_id="L4-001", severity=Severity.HIGH, message="bad", location="/tmp", evidence={})],
            verdict=BehavioralVerdict.SUSPICIOUS,
        )
        mock_engine_fn.return_value = mock_engine

        result = scan_workspace(tmp_path, fail_on="HIGH")
        assert result.total_findings >= 1
        assert result.failed_projects >= 1

    @patch("picosentry.sandbox.workspace.sandbox_run")
    @patch("picosentry.sandbox.workspace.profile_from_sandbox_result")
    @patch("picosentry.sandbox.workspace.create_default_engine")
    def test_scan_sandbox_exception(self, mock_engine_fn, mock_profile, mock_sandbox, tmp_path):
        self._make_project(tmp_path)
        mock_sandbox.side_effect = RuntimeError("sandbox failed")
        mock_engine = MagicMock()
        mock_engine_fn.return_value = mock_engine

        result = scan_workspace(tmp_path)
        assert result.failed_projects >= 1
        assert len(result.errors) >= 1

    @patch("picosentry.sandbox.workspace.sandbox_run")
    @patch("picosentry.sandbox.workspace.profile_from_sandbox_result")
    @patch("picosentry.sandbox.workspace.create_default_engine")
    def test_scan_multiple_projects(self, mock_engine_fn, mock_profile, mock_sandbox, tmp_path):
        self._make_project(tmp_path, name="proj-a", ptype="node")
        self._make_project(tmp_path, name="proj-b", ptype="python")
        mock_sandbox.return_value = _make_sandbox_result()
        mock_profile.return_value = BehavioralProfile(
            package="proj", entrypoint="echo", total_runtime_ms=10, exit_code=0
        )
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = _make_analysis()
        mock_engine_fn.return_value = mock_engine

        result = scan_workspace(tmp_path)
        assert result.total_projects == 2
        assert result.scanned_projects == 2

    @patch("picosentry.sandbox.workspace.sandbox_run")
    @patch("picosentry.sandbox.workspace.profile_from_sandbox_result")
    @patch("picosentry.sandbox.workspace.create_default_engine")
    def test_scan_empty_workspace(self, mock_engine_fn, mock_profile, mock_sandbox, tmp_path):
        mock_engine = MagicMock()
        mock_engine_fn.return_value = mock_engine

        result = scan_workspace(tmp_path)
        assert result.total_projects == 0
        assert result.scanned_projects == 0

    @patch("picosentry.sandbox.workspace.sandbox_run")
    @patch("picosentry.sandbox.workspace.profile_from_sandbox_result")
    @patch("picosentry.sandbox.workspace.create_default_engine")
    def test_scan_custom_commands(self, mock_engine_fn, mock_profile, mock_sandbox, tmp_path):
        proj = self._make_project(tmp_path)
        mock_sandbox.return_value = _make_sandbox_result()
        mock_profile.return_value = BehavioralProfile(
            package="proj", entrypoint="npm", total_runtime_ms=10, exit_code=0
        )
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = _make_analysis()
        mock_engine_fn.return_value = mock_engine

        commands = {str(proj): [["npm", "run", "build"]]}
        result = scan_workspace(tmp_path, commands=commands)
        assert result.scanned_projects == 1

    @patch("picosentry.sandbox.workspace.sandbox_run")
    @patch("picosentry.sandbox.workspace.profile_from_sandbox_result")
    @patch("picosentry.sandbox.workspace.create_default_engine")
    def test_scan_duration_ms(self, mock_engine_fn, mock_profile, mock_sandbox, tmp_path):
        self._make_project(tmp_path)
        mock_sandbox.return_value = _make_sandbox_result()
        mock_profile.return_value = BehavioralProfile(
            package="proj", entrypoint="echo", total_runtime_ms=10, exit_code=0
        )
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = _make_analysis()
        mock_engine_fn.return_value = mock_engine

        result = scan_workspace(tmp_path)
        assert result.duration_ms >= 0

    @patch("picosentry.sandbox.workspace.sandbox_run")
    @patch("picosentry.sandbox.workspace.profile_from_sandbox_result")
    @patch("picosentry.sandbox.workspace.create_default_engine")
    def test_scan_fail_on_critical(self, mock_engine_fn, mock_profile, mock_sandbox, tmp_path):
        self._make_project(tmp_path)
        mock_sandbox.return_value = _make_sandbox_result()
        mock_profile.return_value = BehavioralProfile(
            package="proj", entrypoint="echo", total_runtime_ms=10, exit_code=0
        )
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = _make_analysis(
            findings=[Finding(rule_id="L4-002", severity=Severity.MEDIUM, message="meh", location="/tmp", evidence={})],
            verdict=BehavioralVerdict.SUSPICIOUS,
        )
        mock_engine_fn.return_value = mock_engine

        # Medium finding should not fail when fail_on="CRITICAL"
        result = scan_workspace(tmp_path, fail_on="CRITICAL")
        assert result.scanned_projects == 1
        assert result.failed_projects == 0

    @patch("picosentry.sandbox.workspace.sandbox_run")
    @patch("picosentry.sandbox.workspace.profile_from_sandbox_result")
    @patch("picosentry.sandbox.workspace.create_default_engine")
    def test_scan_no_commands_skips_project(self, mock_engine_fn, mock_profile, mock_sandbox, tmp_path):
        proj = tmp_path / "custom-proj"
        proj.mkdir()
        (proj / "package.json").write_text('{"name":"proj"}')
        mock_engine = MagicMock()
        mock_engine_fn.return_value = mock_engine

        # Override commands with empty list to skip
        commands = {str(proj): []}
        result = scan_workspace(tmp_path, commands=commands)
        assert result.total_projects == 1
        # No commands means the project is skipped (not added to results)
        assert str(proj) not in result.projects
        assert result.scanned_projects == 0


# ── scan_workspace_to_json ────────────────────────────────────────────────────


class TestScanWorkspaceToJson:
    @patch("picosentry.sandbox.workspace.scan_workspace")
    def test_returns_json(self, mock_scan, tmp_path):
        wr = WorkspaceResult()
        wr.total_projects = 1
        wr.scanned_projects = 1
        mock_scan.return_value = wr

        result = scan_workspace_to_json(tmp_path)
        data = json.loads(result)
        assert "summary" in data
        assert data["summary"]["total_projects"] == 1

    @patch("picosentry.sandbox.workspace.scan_workspace")
    def test_writes_output_file(self, mock_scan, tmp_path):
        wr = WorkspaceResult()
        wr.total_projects = 0
        mock_scan.return_value = wr

        output = tmp_path / "results.json"
        scan_workspace_to_json(tmp_path, output=output)
        assert output.exists()
        written = json.loads(output.read_text())
        assert "summary" in written

    @patch("picosentry.sandbox.workspace.scan_workspace")
    def test_includes_workspace_root(self, mock_scan, tmp_path):
        wr = WorkspaceResult()
        mock_scan.return_value = wr

        result = scan_workspace_to_json(tmp_path)
        data = json.loads(result)
        assert "workspace_root" in data
