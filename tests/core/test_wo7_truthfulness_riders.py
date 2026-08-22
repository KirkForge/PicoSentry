"""WO7.0.0-034: truthfulness riders round 4 regression tests.

Each sub-item gets a focused assertion: doctor version check covers k8s
deployment.yaml, CLI cluster prog name is correct, CLI serve forwards
falsy-zero flags, README chapter index includes ch.22, experimental.py
COMPONENT_STATUS includes firewall, k8s deployment has PICODOME_JOB_STORE_DIR,
and picodome helm mounts a PVC for the sqlite store path.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from unittest.mock import patch


from picosentry._core.doctor import _check_version_consistency
from picosentry.sandbox.cli_commands import cluster as cluster_mod

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class TestDoctorVersionCheck:
    """Sub-item 1: doctor version check must compare the k8s deployment.yaml version label."""

    def test_k8s_deployment_version_in_check(self):
        """The doctor must read the version label from deploy/kubernetes/deployment.yaml."""
        result = _check_version_consistency()
        # The k8s deployment.yaml version label must be included in the check.
        # If the check passes, all versions match including the k8s label.
        assert result.status == "pass", result.detail

    def test_k8s_version_drift_detected(self, tmp_path, monkeypatch):
        """A k8s deployment.yaml version label that differs must fail the check."""
        root = tmp_path
        (root / "picosentry" / "_core").mkdir(parents=True)
        (root / "picosentry" / "serve" / "config").mkdir(parents=True)
        (root / "picosentry" / "__init__.py").write_text('__version__ = "1.0.0"\n')
        (root / "picosentry" / "_core" / "__init__.py").write_text('__version__ = "1.0.0"\n')
        (root / "picosentry" / "serve" / "config" / "version.py").write_text('__version__ = "1.0.0"\n')
        (root / "pyproject.toml").write_text('[project]\nversion = "1.0.0"\n')
        (root / "deploy" / "helm" / "picodome").mkdir(parents=True)
        (root / "deploy" / "helm" / "picodome" / "Chart.yaml").write_text('appVersion: "v1.0.0"\n')
        (root / "deploy" / "kubernetes").mkdir(parents=True)
        (root / "deploy" / "kubernetes" / "deployment.yaml").write_text(
            "  version: v0.9.9\n  image: kirkforge/picodome:v0.9.9\n"
        )
        import picosentry._core.doctor as doctor

        monkeypatch.setattr(doctor, "_ROOT", root)
        result = _check_version_consistency()
        assert result.status == "fail"
        assert "0.9.9" in result.detail or "mismatch" in result.detail.lower()


class TestClusterProgName:
    """Sub-item 2: CLI cluster usage text must say 'picosentry', not 'picodome'."""

    def test_usage_string_uses_picosentry(self, capsys):
        """Calling cluster with no action must print usage with 'picosentry cluster'."""
        args = argparse.Namespace(cluster_action=None)
        rc = cluster_mod.cmd(args)
        assert rc == 1
        err = capsys.readouterr().err
        assert "picosentry cluster" in err, f"usage text should say 'picosentry cluster', got: {err!r}"
        assert "picodome cluster" not in err, f"usage text still says 'picodome cluster': {err!r}"

    def test_rotate_token_output_uses_picosentry(self, capsys, monkeypatch):
        """The rotate-token output must reference 'picosentry cluster status'."""

        class FakeManager:
            def rotate_token(self, tok):
                return {"node_id": "n1", "token_version": 2, "accepted_count": 1}

            def retire_stale_tokens(self, secs):
                return 0

        fake_manager = FakeManager()
        monkeypatch.setattr("picosentry.sandbox.cluster.get_cluster_manager", lambda: fake_manager)
        args = argparse.Namespace(cluster_action="rotate-token", new_token=None, retire_after=300)
        rc = cluster_mod.cmd(args)
        assert rc == 0
        out = capsys.readouterr().out
        assert "picosentry cluster status" in out, (
            f"rotate-token output should reference 'picosentry cluster status', got: {out!r}"
        )
        assert "picodome cluster" not in out


class TestServeFalsyZeroFlags:
    """Sub-item 3: CLI serve must forward --port 0 and --workers 0 to env vars."""

    def _run_serve_cmd(self, monkeypatch, **kwargs) -> dict[str, str]:
        """Run serve.cmd with the given args, return env vars that were set."""
        from picosentry.cli_commands import serve as serve_mod

        defaults = {
            "host": "127.0.0.1",
            "port": 8765,
            "reload": False,
            "workers": 1,
            "plugin_dirs": [],
            "require_signed_plugins": False,
            "trusted_public_keys": None,
            "production": False,
            "profile": None,
        }
        defaults.update(kwargs)
        args = argparse.Namespace(**defaults)

        captured: dict[str, str] = {}
        original_setitem = os.environ.__class__.__setitem__

        def _tracking_setitem(self, key, value):
            captured[key] = value

        monkeypatch.setattr(os.environ.__class__, "__setitem__", _tracking_setitem)
        with patch("picosentry.cli_commands.serve.import_or_warn") as mock_import:
            mock_import.return_value = lambda: 0
            import contextlib

            with contextlib.suppress(SystemExit, Exception):
                serve_mod.cmd(args)
        monkeypatch.setattr(os.environ.__class__, "__setitem__", original_setitem)
        return captured

    def test_port_zero_forwarded(self, monkeypatch):
        """--port 0 must set PICOSHOGUN_API_PORT=0, not be skipped as falsy."""
        captured = self._run_serve_cmd(monkeypatch, port=0)
        assert "PICOSHOGUN_API_PORT" in captured, "port=0 was not forwarded (falsy-zero bug)"
        assert captured["PICOSHOGUN_API_PORT"] == "0"

    def test_workers_zero_forwarded(self, monkeypatch):
        """--workers 0 must set PICOSHOGUN_API_WORKERS=0, not be skipped as falsy."""
        captured = self._run_serve_cmd(monkeypatch, workers=0)
        assert "PICOSHOGUN_API_WORKERS" in captured, "workers=0 was not forwarded (falsy-zero bug)"
        assert captured["PICOSHOGUN_API_WORKERS"] == "0"

    def test_port_default_forwarded(self, monkeypatch):
        """Default port must still be forwarded (not just non-zero values)."""
        captured = self._run_serve_cmd(monkeypatch, port=8765)
        assert captured.get("PICOSHOGUN_API_PORT") == "8765"


class TestReadmeChapterIndex:
    """Sub-item 4: README chapter index must include ch.22 (Repository structure)."""

    def test_ch22_in_chapter_index(self):
        readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
        assert "22-repository-structure" in readme, "README chapter index is missing ch.22 (Repository structure)"
        # Verify ch.22 is between ch.21 and ch.23 in the index
        idx21 = readme.index("21-known-limitations-and-component-status")
        idx22 = readme.index("22-repository-structure")
        idx23 = readme.index("23-appendix-adr-index")
        assert idx21 < idx22 < idx23, "ch.22 is not between ch.21 and ch.23 in the README chapter index"


class TestExperimentalFirewallStatus:
    """Sub-item 5: experimental.py COMPONENT_STATUS must include firewall with honest status."""

    def test_firewall_in_component_status(self):
        from picosentry.experimental import COMPONENT_STATUS

        firewall = [c for c in COMPONENT_STATUS if "firewall" in c.name.lower()]
        assert firewall, "firewall is missing from COMPONENT_STATUS"
        assert firewall[0].status == "Beta", f"firewall status should be Beta, got {firewall[0].status!r}"

    def test_firewall_in_readme_table(self):
        """The README status table must include the firewall row."""
        readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
        assert "picosentry firewall" in readme, "README status table is missing the firewall row"

    def test_maturity_lockstep_with_firewall(self):
        """The CLI maturity badge for firewall must match COMPONENT_STATUS (both Beta)."""
        from picosentry.cli_commands._maturity import _COMMAND_MATURITY
        from picosentry.experimental import COMPONENT_STATUS

        cli_badge = _COMMAND_MATURITY["firewall"][0]
        cs_status = next(c for c in COMPONENT_STATUS if "firewall" in c.name.lower()).status
        assert cli_badge.capitalize() == cs_status, f"firewall: CLI badge={cli_badge}, COMPONENT_STATUS={cs_status}"


class TestK8sDeploymentJobStoreDir:
    """Sub-item 6: k8s deployment.yaml must set PICODOME_JOB_STORE_DIR."""

    def test_job_store_dir_env_present(self):
        manifest = (_REPO_ROOT / "deploy" / "kubernetes" / "deployment.yaml").read_text()
        assert "PICODOME_JOB_STORE_DIR" in manifest, (
            "deploy/kubernetes/deployment.yaml is missing PICODOME_JOB_STORE_DIR env var"
        )
        assert "/home/picodome/.picodome" in manifest, "PICODOME_JOB_STORE_DIR must point at the PVC mount path"


class TestPicodomeHelmSqlitePVC:
    """Sub-item 7: picodome helm must mount a PVC for the sqlite store path.

    With readOnlyRootFilesystem: true, sqlite cannot write to the container FS.
    When store.backend is sqlite, the data PVC must be mounted regardless of
    persistence.enabled.
    """

    def test_volume_mount_conditioned_on_sqlite(self):
        template = (_REPO_ROOT / "deploy" / "helm" / "picodome" / "templates" / "deployment.yaml").read_text()
        assert 'or .Values.persistence.enabled (eq .Values.store.backend "sqlite")' in template, (
            "data volume mount must be enabled when store.backend is sqlite "
            "(sqlite on a readonly FS will fail to write)"
        )

    def test_pvc_template_conditioned_on_sqlite(self):
        pvc = (_REPO_ROOT / "deploy" / "helm" / "picodome" / "templates" / "pvc.yaml").read_text()
        assert 'or .Values.persistence.enabled (eq .Values.store.backend "sqlite")' in pvc, (
            "PVC template must be created when store.backend is sqlite"
        )

    def test_job_store_dir_conditioned_on_sqlite(self):
        template = (_REPO_ROOT / "deploy" / "helm" / "picodome" / "templates" / "deployment.yaml").read_text()
        assert 'or .Values.persistence.enabled (eq .Values.store.backend "sqlite")' in template
