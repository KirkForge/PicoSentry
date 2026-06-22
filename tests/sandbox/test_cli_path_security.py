"""Tests for sandbox CLI path containment on --policy and --cwd."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _clear_workspace_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each test gets a clean workspace-root env."""
    monkeypatch.delenv("PICODOME_WORKSPACE_ROOT", raising=False)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """Return a temp directory to use as the workspace root."""
    return tmp_path


class TestResolveExternalPath:
    def test_rejects_url_like_path(self, workspace: Path) -> None:
        from picosentry.sandbox.cli_commands._common import _resolve_external_path

        result = _resolve_external_path(
            "http://example.com/policy.json",
            workspace,
            must_exist=False,
            description="--policy",
        )
        assert result is None

    def test_rejects_path_outside_workspace(self, workspace: Path) -> None:
        from picosentry.sandbox.cli_commands._common import _resolve_external_path

        outside = Path("/etc/passwd")
        result = _resolve_external_path(
            str(outside),
            workspace,
            must_exist=False,
            description="--policy",
        )
        assert result is None

    def test_rejects_symlink_escaping_workspace(self, workspace: Path) -> None:
        from picosentry.sandbox.cli_commands._common import _resolve_external_path

        # Create the real file outside the workspace root so the symlink escapes.
        outside_dir = Path(tempfile.mkdtemp())
        try:
            real_file = outside_dir / "target.json"
            real_file.write_text("{}")
            symlink = workspace / "link.json"
            symlink.symlink_to(real_file)

            result = _resolve_external_path(
                str(symlink),
                workspace,
                must_exist=True,
                description="--policy",
            )
            assert result is None
        finally:
            real_file.unlink(missing_ok=True)
            symlink.unlink(missing_ok=True)
            outside_dir.rmdir() if outside_dir.exists() else None

    def test_accepts_path_inside_workspace(self, workspace: Path) -> None:
        from picosentry.sandbox.cli_commands._common import _resolve_external_path

        policy_file = workspace / "policy.json"
        policy_file.write_text("{}")

        result = _resolve_external_path(
            str(policy_file),
            workspace,
            must_exist=True,
            description="--policy",
        )
        assert result == policy_file.resolve()

    def test_accepts_path_via_env_workspace_root(self, tmp_path: Path) -> None:
        from picosentry.sandbox.cli_commands._common import _workspace_root

        os.environ["PICODOME_WORKSPACE_ROOT"] = str(tmp_path)
        assert _workspace_root() == tmp_path.resolve()
        del os.environ["PICODOME_WORKSPACE_ROOT"]


class TestSandboxCmdPathContainment:
    def test_rejects_policy_outside_workspace(self, workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PICODOME_WORKSPACE_ROOT", str(workspace))
        from picosentry.sandbox.cli_commands.sandbox import cmd

        args = argparse.Namespace(
            command=["echo", "hi"],
            policy=Path("/etc/passwd"),
            timeout=30.0,
            cwd=None,
            allow_runtime=None,
            deterministic_output=False,
            quiet=True,
            exit_code=False,
            fail_on=None,
            summary=False,
            verbose=False,
            log_format="text",
            backend="subprocess",
            allow_degraded=True,
            format="json",
            verify_determinism=False,
        )

        assert cmd(args) == 2

    def test_rejects_cwd_outside_workspace(self, workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PICODOME_WORKSPACE_ROOT", str(workspace))
        from picosentry.sandbox.cli_commands.sandbox import cmd

        args = argparse.Namespace(
            command=["echo", "hi"],
            policy=None,
            timeout=30.0,
            cwd="/tmp",
            allow_runtime=None,
            deterministic_output=False,
            quiet=True,
            exit_code=False,
            fail_on=None,
            summary=False,
            verbose=False,
            log_format="text",
            backend="subprocess",
            allow_degraded=True,
            format="json",
            verify_determinism=False,
        )

        assert cmd(args) == 2
