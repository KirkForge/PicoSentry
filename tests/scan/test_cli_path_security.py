"""Tests for scanner CLI path containment and update source controls."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from picosentry.scan.cli_commands.scan import _resolve_external_path, _workspace_root, cmd as scan_cmd
from picosentry.scan.cli_commands.update import _is_source_allowed, cmd as update_cmd
from picosentry.scan.config import PicoSentryConfig


class TestWorkspaceRoot:
    """Workspace root defaults and overrides."""

    def test_default_is_cwd(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PICOSENTRY_SCANS_WORKSPACE_ROOT", raising=False)
        assert _workspace_root() == Path.cwd()

    def test_env_override(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("PICOSENTRY_SCANS_WORKSPACE_ROOT", str(tmp_path))
        assert _workspace_root() == tmp_path.resolve()


class TestResolveExternalPath:
    """Path validation rejects URLs, symlinks, and traversal."""

    def test_rejects_remote_url(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="remote URL"):
            _resolve_external_path("https://example.com/corpus", tmp_path, description="--corpus")

    def test_rejects_symlink(self, tmp_path: Path) -> None:
        real_file = tmp_path / "real.txt"
        real_file.write_text("data")
        link = tmp_path / "link.txt"
        link.symlink_to(real_file)
        with pytest.raises(ValueError, match="symlink"):
            _resolve_external_path(str(link), tmp_path, description="--corpus")

    def test_rejects_path_traversal(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="inside the workspace root"):
            _resolve_external_path(str(tmp_path / ".." / "outside.txt"), tmp_path, description="--output")

    def test_accepts_path_inside_workspace(self, tmp_path: Path) -> None:
        inside = tmp_path / "inside.txt"
        inside.write_text("data")
        resolved = _resolve_external_path(str(inside), tmp_path, description="--output")
        assert resolved == inside.resolve()


class TestScanCommandPathContainment:
    """scan CLI enforces workspace containment for external file arguments."""

    def _make_args(self, target: Path, **kwargs: object) -> argparse.Namespace:
        defaults = {
            "target": str(target),
            "verbose": False,
            "format": "table",
            "output": None,
            "corpus": None,
            "advisory_db": None,
            "baseline": None,
            "policy": None,
            "sarif_file": None,
            "offline": False,
            "severity": None,
            "deterministic_output": False,
            "verify_determinism": False,
            "timeout": 300,
            "baseline_update": False,
        }
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_rejects_output_outside_workspace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PICOSENTRY_SCANS_WORKSPACE_ROOT", str(tmp_path))
        target = tmp_path / "project"
        target.mkdir()
        (target / "package.json").write_text("{}")

        outside = Path(tempfile.gettempdir()) / "picosentry_outside_output.json"
        args = self._make_args(target, output=str(outside))

        rc = scan_cmd(args)
        assert rc == 2

    def test_accepts_output_inside_workspace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PICOSENTRY_SCANS_WORKSPACE_ROOT", str(tmp_path))
        target = tmp_path / "project"
        target.mkdir()
        (target / "package.json").write_text("{}")
        output = target / "output.json"

        args = self._make_args(target, output=str(output), format="json")

        # Avoid executing the real engine by stubbing the scan runner.
        with patch("picosentry.scan.cli_commands.scan._run_scan") as mock_run:
            from picosentry.scan.models import ScanResult, ScanStats

            mock_run.return_value = ScanResult(
                target=str(target),
                engine_version="test",
                corpus_version="test",
                findings=[],
                stats=ScanStats(),
            )
            rc = scan_cmd(args)

        assert rc == 0
        assert output.exists()


class TestUpdateOfflineAndAllowList:
    """update command respects offline mode and source URL allow-lists."""

    def test_update_offline_flag_returns_2(self, tmp_path: Path) -> None:
        args = argparse.Namespace(
            ecosystem="npm",
            top=2,
            output=str(tmp_path),
            source_url=None,
            merge=True,
            offline=True,
        )
        assert update_cmd(args) == 2

    def test_update_offline_env_returns_2(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("PICOSENTRY_OFFLINE", "1")
        args = argparse.Namespace(
            ecosystem="npm",
            top=2,
            output=str(tmp_path),
            source_url=None,
            merge=True,
            offline=False,
        )
        assert update_cmd(args) == 2

    def test_update_disallowed_source_blocked(self, tmp_path: Path) -> None:
        args = argparse.Namespace(
            ecosystem="npm",
            top=2,
            output=str(tmp_path),
            source_url=None,
            merge=True,
            offline=False,
        )

        config = PicoSentryConfig()
        config.updates_enabled = True
        config.updates_allowed_sources = ["https://allowed.example.com/"]

        with (
            patch("picosentry.scan.cli_commands.update.load_config", return_value=config),
            patch(
                "picosentry.scan.cli_commands.update._fetch_ecosystem",
                return_value=(["express"], "https://github.com/example/raw.json", False),
            ),
        ):
            rc = update_cmd(args)

        assert rc == 1

    def test_update_allowed_source_permitted(self, tmp_path: Path) -> None:
        args = argparse.Namespace(
            ecosystem="npm",
            top=2,
            output=str(tmp_path),
            source_url=None,
            merge=True,
            offline=False,
        )

        config = PicoSentryConfig()
        config.updates_enabled = True
        config.updates_allowed_sources = ["https://github.com/"]

        with (
            patch("picosentry.scan.cli_commands.update.load_config", return_value=config),
            patch(
                "picosentry.scan.cli_commands.update._fetch_ecosystem",
                return_value=(["express"], "https://github.com/example/raw.json", False),
            ),
            patch("picosentry.scan.cli_commands.update._write_manifest"),
        ):
            rc = update_cmd(args)

        assert rc == 0


class TestIsSourceAllowed:
    """Unit tests for source URL allow-list matching."""

    def test_empty_allow_list_permits_everything(self) -> None:
        assert _is_source_allowed("https://anywhere.example.com/data", []) is True

    def test_exact_match(self) -> None:
        assert _is_source_allowed("https://example.com/data.json", ["https://example.com/data.json"]) is True

    def test_prefix_match(self) -> None:
        assert _is_source_allowed("https://example.com/data/v1", ["https://example.com/data"]) is True

    def test_hostname_match(self) -> None:
        assert _is_source_allowed("https://example.com/data", ["example.com"]) is True

    def test_host_mismatch_rejected(self) -> None:
        assert _is_source_allowed("https://evil.com/data", ["example.com"]) is False
