"""Version-drift guards.

PicoSentry has historically had version strings drift between the top-level
package, the per-subpackage __init__.py files, the wheel metadata, and the
Helm chart.  This module asserts they stay in lockstep so a release can't
ship with a stale subpackage version again.

The source of truth is the ``[project] version`` field in ``pyproject.toml``.
Every other place a version string is published must match it.
"""

from __future__ import annotations

import gzip
import importlib.util
import io
import os
import re
import shutil
import subprocess
import tarfile
import urllib.error
import urllib.request
from pathlib import Path
from types import ModuleType

import pytest

import picosentry
from picosentry import _core, sandbox, scan, watch
from picosentry.serve.config import version as serve_version

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _read_pyproject_version() -> str:
    text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
    # [project] may have other fields (name, description, ...) before the
    # version line; match within the [project] block only.
    block = re.search(r"^\[project\](?P<body>.*?)(?=^\[)", text, re.MULTILINE | re.DOTALL)
    if not block:
        raise AssertionError("pyproject.toml is missing a [project] table")
    match = re.search(r'^version\s*=\s*"([^"]+)"', block.group("body"), re.MULTILINE)
    if not match:
        raise AssertionError("pyproject.toml [project] table is missing a version field")
    return match.group(1)


def test_top_level_version_is_set() -> None:
    """The top-level version is the source of truth; must be non-empty."""
    assert picosentry.__version__
    assert isinstance(picosentry.__version__, str)


def test_subpackage_versions_match_top_level() -> None:
    """Every per-subpackage __version__ must equal the top-level version.

    Drift here is what produced the v2.0.12 release with scan/watch still
    reporting v2.0.9.  ``serve`` carries its version one level deeper than
    the others (``picosentry.serve.config.version.__version__``) — that
    module is the one to keep in lockstep.
    """
    expected = picosentry.__version__
    for name, module in [
        ("_core", _core),
        ("scan", scan),
        ("watch", watch),
        ("sandbox", sandbox),
        ("serve.config.version", serve_version),
    ]:
        actual = getattr(module, "__version__", None)
        assert actual == expected, (
            f"picosentry.{name}.__version__ = {actual!r}, expected {expected!r} (top-level picosentry.__version__)"
        )


def test_pyproject_version_matches_top_level() -> None:
    """The wheel's [project] version must equal the runtime version."""
    assert _read_pyproject_version() == picosentry.__version__


def test_helm_chart_app_version_matches() -> None:
    """The Helm chart's appVersion must equal the v-prefixed package version.

    The chart's own ``version`` (chart release) is allowed to lag — that
    field tracks chart-template revisions, not the app inside the chart.

    Every release path publishes v-prefixed registry tags (release.yml bake
    TAG override, scripts/build_docker_multiarch.sh), and the deployment
    template defaults the image tag to appVersion — so a bare "2.1.2"
    rendered ``kirkforge/picodome:2.1.2``, a tag the registry never has
    (WO5.0.0-014 evidence #2).
    """
    expected = f"v{picosentry.__version__}"
    chart = Path(__file__).resolve().parent.parent / "deploy" / "helm" / "picodome" / "Chart.yaml"
    if not chart.exists():
        pytest.skip(f"Helm chart not present: {chart}")
    text = chart.read_text()
    match = re.search(r'^appVersion:\s*"([^"]+)"', text, re.MULTILINE)
    assert match, f"Helm chart is missing an appVersion field: {chart}"
    assert match.group(1) == expected, f"Helm chart appVersion = {match.group(1)!r}, expected {expected!r}"


def test_helm_chart_renders_v_prefixed_image_tag() -> None:
    """A default ``helm install`` must resolve a tag the registry actually has.

    Renders with ``helm template`` when the binary is available; otherwise
    parses the chart files and mirrors the deployment template's
    ``image.tag | default .Chart.AppVersion`` logic.
    """
    chart_dir = _REPO_ROOT / "deploy" / "helm" / "picodome"
    expected = f"kirkforge/picodome:v{picosentry.__version__}"
    helm = shutil.which("helm")
    if helm is not None:
        rendered = subprocess.run(
            [helm, "template", "picodome", str(chart_dir)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        images = re.findall(r'^\s*image:\s*"?([^\s"]+)"?', rendered, re.MULTILINE)
        assert images, "helm template produced no image: lines"
        for image in images:
            assert image == expected, f"rendered image {image!r}, expected {expected!r}"
        return
    values = (chart_dir / "values.yaml").read_text()
    tag = re.search(r'^\s*tag:\s*"([^"]*)"', values, re.MULTILINE)
    assert tag and tag.group(1) == "", "values.yaml image.tag must stay empty so appVersion is the default"
    template = (chart_dir / "templates" / "deployment.yaml").read_text()
    assert "default .Chart.AppVersion" in template, "deployment template no longer defaults the tag to appVersion"
    app_version = re.search(r'^appVersion:\s*"([^"]+)"', (chart_dir / "Chart.yaml").read_text(), re.MULTILINE)
    assert app_version, "Chart.yaml is missing appVersion"
    assert f"kirkforge/picodome:{app_version.group(1)}" == expected


def test_experimental_notes_version_lockstep() -> None:
    """The experimental honesty table must quote the current version.

    ``picosentry/experimental.py`` names the Docker tag and the published
    PyPI version in its notes; a missed bump ships a stale table (the exact
    drift class WO4.0.0-009 was cut for).
    """
    src = (_REPO_ROOT / "picosentry" / "experimental.py").read_text()
    assert f"picodome:v{picosentry.__version__}" in src, "experimental.py Docker tag is stale"
    assert f"v{picosentry.__version__} published" in src, "experimental.py PyPI note is stale"


def test_readme_version_lockstep() -> None:
    """README install/pull pointers must quote the current version."""
    text = (_REPO_ROOT / "README.md").read_text()
    assert f"picodome:v{picosentry.__version__}" in text, "README Docker pull line is stale"


def test_manual_version_lockstep() -> None:
    """manual.md header + engine line must quote the current version
    (WO6.0.0-021 item 4). manual.md was an unguarded lockstep surface —
    a missed bump shipped a stale manual while the wheel moved on."""
    text = (_REPO_ROOT / "docs" / "manual.md").read_text()
    # Line 3 header: "Version X.Y.Z — BUSL-1.1 — ..."
    assert f"Version {picosentry.__version__}" in text, "manual.md header version is stale"
    # Engine line in the quick-start banner.
    assert f"Engine: v{picosentry.__version__}" in text, "manual.md Engine banner is stale"


def test_uv_lock_version_lockstep() -> None:
    """uv.lock's picosentry package version must match the runtime version
    (WO6.0.0-021 item 4). uv.lock was an unguarded lockstep surface — the
    SARIF-incident class: a `uv lock` after a bump that didn't get committed
    shipped a stale lockfile while the wheel reported the new version."""
    import re as _re

    text = (_REPO_ROOT / "uv.lock").read_text()
    # The picosentry package block: [[package]] \n name = "picosentry" \n version = "X.Y.Z"
    m = _re.search(r'name = "picosentry"\s*\nversion = "([^"]+)"', text)
    assert m, "uv.lock has no picosentry package block"
    assert m.group(1) == picosentry.__version__, (
        f"uv.lock picosentry version = {m.group(1)!r}, expected {picosentry.__version__!r}"
    )


def test_kubernetes_manifest_image_lockstep() -> None:
    """deploy/kubernetes/deployment.yaml must pin the current image tag.

    It shipped v2.0.16 while the package was at v2.1.1 — three releases
    stale, unguarded (WO4.0.0-009 evidence #3).
    """
    manifest = (_REPO_ROOT / "deploy" / "kubernetes" / "deployment.yaml").read_text()
    match = re.search(r"^\s*image:\s*(\S+)", manifest, re.MULTILINE)
    assert match, "deployment.yaml has no image: line"
    assert match.group(1) == f"kirkforge/picodome:v{picosentry.__version__}", (
        f"deployment.yaml image = {match.group(1)!r}, expected 'kirkforge/picodome:v{picosentry.__version__}'"
    )


@pytest.mark.network
def test_docker_hub_carries_current_version_tag() -> None:
    """The Docker Hub registry must carry the current version's image tag.

    The docs claimed ``kirkforge/picodome:v2.1.2`` existed while the Hub's
    newest tag was v2.0.18 — nothing verified registry existence
    (WO5.0.0-014 evidence #1). release.yml now hard-fails on a missing tag
    post-push; this is the local/CI counterpart.

    Opt-in via ``PICOSENTRY_CHECK_REGISTRY=1``: the check needs network and
    a completed push. The v2.1.2 git tag predates the image push, so
    "released" cannot imply "pushed" — enforcement is deliberate, not
    automatic. Fails on an authoritative 404; skips when the Hub cannot be
    reached (an unreachable registry proves nothing either way).
    """
    if os.environ.get("PICOSENTRY_CHECK_REGISTRY") != "1":
        pytest.skip("set PICOSENTRY_CHECK_REGISTRY=1 to verify the Docker Hub tag")
    tag = f"v{picosentry.__version__}"
    url = f"https://hub.docker.com/v2/repositories/kirkforge/picodome/tags/{tag}"
    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            assert response.status == 200
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            pytest.fail(
                f"kirkforge/picodome:{tag} is not on Docker Hub — push it "
                f"(scripts/build_docker_multiarch.sh --push) or correct the pending-push claims"
            )
        pytest.skip(f"Docker Hub returned HTTP {exc.code} for {tag} — cannot verify")
    except OSError as exc:
        pytest.skip(f"cannot reach Docker Hub: {exc}")


def _load_normalizer() -> ModuleType:
    path = _REPO_ROOT / "scripts" / "normalize_sdist.py"
    spec = importlib.util.spec_from_file_location("normalize_sdist", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_fixture_sdist(path: Path, mtime: int, uid: int, gzip_mtime: int) -> None:
    """A stand-in sdist with the metadata setuptools fails to normalize."""
    payload = b"Metadata-Version: 2.1\nName: picosentry\n"
    raw = io.BytesIO()
    with tarfile.TarFile(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        directory = tarfile.TarInfo("picosentry-9.9.9/picosentry/")
        directory.type = tarfile.DIRTYPE
        directory.mtime, directory.uid, directory.uname = mtime, uid, "builder"
        tar.addfile(directory)
        info = tarfile.TarInfo("picosentry-9.9.9/PKG-INFO")
        info.size = len(payload)
        info.mtime, info.uid, info.uname = mtime, uid, "builder"
        tar.addfile(info, io.BytesIO(payload))
    with path.open("wb") as f, gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=gzip_mtime) as gz:
        gz.write(raw.getvalue())


def test_normalize_sdist_two_builds_hash_identically(tmp_path: Path) -> None:
    """Two differently-stamped builds, normalized, must be byte-identical.

    Stand-in for building the real sdist twice (setuptools leaves differing
    dir-entry mtimes, uids and gzip headers) — the property release.yml and
    the push-tier reproducible-build job rely on.
    """
    normalizer = _load_normalizer()
    a, b = tmp_path / "a.tar.gz", tmp_path / "b.tar.gz"
    _write_fixture_sdist(a, mtime=1_700_000_000, uid=1000, gzip_mtime=1_700_000_000)
    _write_fixture_sdist(b, mtime=1_800_000_000, uid=0, gzip_mtime=1_800_000_000)
    assert a.read_bytes() != b.read_bytes(), "fixture builds should differ pre-normalization"

    norm_a, norm_b = tmp_path / "norm-a.tar.gz", tmp_path / "norm-b.tar.gz"
    normalizer.normalize_sdist(a, norm_a, epoch=1_600_000_000)
    normalizer.normalize_sdist(b, norm_b, epoch=1_600_000_000)
    assert norm_a.read_bytes() == norm_b.read_bytes()


def test_normalize_sdist_clamps_member_metadata(tmp_path: Path) -> None:
    """Normalized members carry epoch mtimes and root ownership."""
    normalizer = _load_normalizer()
    src, dst = tmp_path / "a.tar.gz", tmp_path / "norm.tar.gz"
    _write_fixture_sdist(src, mtime=1_700_000_000, uid=1000, gzip_mtime=1_700_000_000)
    normalizer.normalize_sdist(src, dst, epoch=1_600_000_000)
    with tarfile.open(dst) as tar:
        members = tar.getmembers()
        assert len(members) == 2
        for member in members:
            assert member.mtime == 1_600_000_000
            assert (member.uid, member.gid, member.uname, member.gname) == (0, 0, "root", "root")
        # file content survives the rewrite
        assert tar.extractfile("picosentry-9.9.9/PKG-INFO").read().startswith(b"Metadata-Version")


class TestGateTruthfulness:
    """CI gates that look like verification must be able to fail (WO5.0.0-025).

    The action run step, the GitLab template script and the verify-release
    attestation step are executed against stubbed tools so their failure
    paths are proven, not assumed.
    """

    SARIF_EMPTY = '{"runs": [{"results": []}]}'
    SARIF_TWO = '{"runs": [{"results": ["a", "b"]}]}'

    @staticmethod
    def _run_script(
        script: str, workdir: Path, stubs: dict[str, str], env: dict[str, str]
    ) -> subprocess.CompletedProcess:
        bin_dir = workdir / "bin"
        bin_dir.mkdir(exist_ok=True)
        for name, body in stubs.items():
            stub = bin_dir / name
            stub.write_text(body)
            stub.chmod(0o755)
        script_file = workdir / "script.sh"
        script_file.write_text(script)
        return subprocess.run(
            ["bash", str(script_file)],
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=30,
            env={**env, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"},
        )

    @staticmethod
    def _action_run_block() -> str:
        import yaml

        doc = yaml.safe_load((_REPO_ROOT / "action.yml").read_text())
        steps = doc["runs"]["steps"]
        return next(s["run"] for s in steps if s.get("name") == "Run PicoSentry scan")

    @classmethod
    def _action_script(cls, **inputs: str) -> str:
        values = {
            "format": "sarif",
            "path": ".",
            "sarif-file": "picosentry-results.sarif",
            "severity-threshold": "",
            "fail-on-findings": "true",
            **inputs,
        }
        block = cls._action_run_block()
        return re.sub(
            r"\$\{\{ inputs\.([\w-]+) \}\}",
            lambda m: values[m.group(1)],
            block,
        )

    @staticmethod
    def _picosentry_stub() -> str:
        return (
            "#!/bin/sh\n"
            "printf '%s' \"$PICOSENTRY_STUB_OUTPUT\" > picosentry-results.sarif\n"
            "printf '%s' \"$PICOSENTRY_STUB_OUTPUT\" > sarif.json\n"
            "printf '%s\\n' \"$@\" >> picosentry-args.log\n"
            "exit ${PICOSENTRY_STUB_EXIT:-0}\n"
        )

    def _run_action(self, tmp_path: Path, **inputs: str) -> tuple[subprocess.CompletedProcess, str]:
        stub_output = inputs.pop("stub_output", self.SARIF_EMPTY)
        stub_exit = inputs.pop("stub_exit", "0")
        proc = self._run_script(
            self._action_script(**inputs),
            tmp_path,
            {"picosentry": self._picosentry_stub()},
            {
                "PICOSENTRY_STUB_OUTPUT": stub_output,
                "PICOSENTRY_STUB_EXIT": stub_exit,
                "GITHUB_OUTPUT": str(tmp_path / "github_output.txt"),
            },
        )
        args_log = tmp_path / "picosentry-args.log"
        return proc, (args_log.read_text() if args_log.exists() else "")

    def test_action_forwards_format_input(self, tmp_path):
        proc, args = self._run_action(tmp_path, format="json", stub_output='{"findings": []}')
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "json" in args.split()

    def test_action_rejects_unknown_format(self, tmp_path):
        proc, args = self._run_action(tmp_path, format="bogus")
        assert proc.returncode == 2
        assert "Invalid format" in proc.stdout + proc.stderr
        assert args == ""

    def test_action_sarif_parse_failure_hard_fails(self, tmp_path):
        proc, _ = self._run_action(tmp_path, stub_output="this is not sarif")
        assert proc.returncode == 2
        assert "refusing to report 0 findings" in proc.stdout + proc.stderr

    def test_action_zero_findings_passes(self, tmp_path):
        proc, _ = self._run_action(tmp_path, stub_output=self.SARIF_EMPTY)
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_action_findings_trip_fail_on_findings(self, tmp_path):
        proc, _ = self._run_action(tmp_path, stub_output=self.SARIF_TWO)
        assert proc.returncode == 1

    def test_action_scan_failure_propagates(self, tmp_path):
        proc, _ = self._run_action(tmp_path, stub_exit="2")
        assert proc.returncode == 2
        assert "exit code 2" in proc.stdout + proc.stderr

    def test_action_fail_on_findings_requires_findings_format(self, tmp_path):
        proc, _ = self._run_action(tmp_path, format="cyclonedx", stub_output="{}")
        assert proc.returncode == 2
        assert "findings-bearing format" in proc.stdout + proc.stderr

    def test_action_github_format_uses_sarif_file_not_output(self, tmp_path):
        """format=github must pass --sarif-file (not --output) so the SARIF
        bundle lands at the declared sarif-file path (WO6.0.0-021 item 3).
        Previously --output was the sarif-file path, but the github formatter
        writes SARIF to --sarif-file and the markdown summary to --output, so
        the declared output ended up holding markdown while real SARIF went to
        the hardcoded sarif.json — and the action's count read sarif.json.
        """
        proc, args = self._run_action(tmp_path, format="github", stub_output=self.SARIF_TWO)
        assert proc.returncode == 1, proc.stdout + proc.stderr
        args_list = args.split()
        assert "--sarif-file" in args_list, f"github format must pass --sarif-file, got: {args_list}"
        assert "--output" not in args_list, f"github format must NOT pass --output, got: {args_list}"

    def test_action_sarif_format_uses_output_not_sarif_file(self, tmp_path):
        """format=sarif keeps the original --output path (the SARIF bundle
        is the primary artifact). Regression guard for the item-3 fix."""
        proc, args = self._run_action(tmp_path, format="sarif", stub_output=self.SARIF_EMPTY)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        args_list = args.split()
        assert "--output" in args_list, f"sarif format must pass --output, got: {args_list}"
        assert "--sarif-file" not in args_list, f"sarif format must NOT pass --sarif-file, got: {args_list}"

    @staticmethod
    def _gitlab_script() -> str:
        import yaml

        doc = yaml.safe_load((_REPO_ROOT / "ci-templates" / "gitlab-picosentry.yml").read_text())
        return doc[".picosentry-scan"]["script"][0]

    def _run_gitlab(
        self, tmp_path: Path, stub_output: str, stub_exit: str = "0", **env: str
    ) -> subprocess.CompletedProcess:
        variables = {
            "PICOSENTRY_PATH": ".",
            "PICOSENTRY_FORMAT": "sarif",
            "PICOSENTRY_SEVERITY_THRESHOLD": "LOW",
            "PICOSENTRY_FAIL_ON_FINDINGS": "true",
            **env,
        }
        return self._run_script(
            self._gitlab_script(),
            tmp_path,
            {"picosentry": self._picosentry_stub()},
            {"PICOSENTRY_STUB_OUTPUT": stub_output, "PICOSENTRY_STUB_EXIT": stub_exit, **variables},
        )

    def test_gitlab_sarif_parse_failure_hard_fails(self, tmp_path):
        proc = self._run_gitlab(tmp_path, stub_output="not json")
        assert proc.returncode == 2
        assert "refusing to report 0 findings" in proc.stdout + proc.stderr

    def test_gitlab_zero_findings_passes(self, tmp_path):
        proc = self._run_gitlab(tmp_path, stub_output=self.SARIF_EMPTY)
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_gitlab_findings_trip_fail_on_findings(self, tmp_path):
        proc = self._run_gitlab(tmp_path, stub_output=self.SARIF_TWO)
        assert proc.returncode == 1

    @pytest.mark.parametrize(("scan_exit", "expected"), [("2", 2), ("3", 3), ("4", 4), ("5", 5), ("9", 9)])
    def test_gitlab_failure_exit_codes_fail_job(self, tmp_path, scan_exit, expected):
        proc = self._run_gitlab(tmp_path, stub_output=self.SARIF_EMPTY, stub_exit=scan_exit)
        assert proc.returncode == expected
        assert "PicoSentry scan" in proc.stdout + proc.stderr

    def test_gitlab_scan_exit_1_honored_even_with_zero_count(self, tmp_path):
        proc = self._run_gitlab(tmp_path, stub_output=self.SARIF_EMPTY, stub_exit="1")
        assert proc.returncode == 1

    def test_gitlab_scan_exit_1_passes_when_opted_out(self, tmp_path):
        proc = self._run_gitlab(
            tmp_path, stub_output=self.SARIF_EMPTY, stub_exit="1", PICOSENTRY_FAIL_ON_FINDINGS="false"
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_gitlab_fail_on_findings_requires_findings_format(self, tmp_path):
        proc = self._run_gitlab(tmp_path, stub_output="{}", PICOSENTRY_FORMAT="cyclonedx")
        assert proc.returncode == 2
        assert "findings-bearing format" in proc.stdout + proc.stderr

    @staticmethod
    def _attestation_run_block() -> str:
        import yaml

        doc = yaml.safe_load((_REPO_ROOT / ".github" / "workflows" / "verify-release.yml").read_text())
        steps = doc["jobs"]["verify-docker"]["steps"]
        return next(s["run"] for s in steps if s.get("name") == "Verify Docker image attestation")

    def _run_attestation(self, tmp_path: Path, stubs: dict[str, str]) -> subprocess.CompletedProcess:
        script = self._attestation_run_block()
        script = script.replace("${{ github.repository }}", "KirkForge/PicoSentry")
        script = script.replace("${{ steps.tag.outputs.TAG }}", "9.9.9")
        return self._run_script(script, tmp_path, stubs, {})

    def test_attestation_digest_failure_fails_step(self, tmp_path):
        proc = self._run_attestation(tmp_path, {"docker": "#!/bin/sh\nexit 1\n"})
        assert proc.returncode == 1
        assert "cannot verify attestation" in proc.stdout + proc.stderr

    def test_attestation_skips_only_when_provably_unattested(self, tmp_path):
        proc = self._run_attestation(
            tmp_path, {"docker": "#!/bin/sh\necho sha256:abc123\n", "gh": "#!/bin/sh\necho 0\n"}
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "not attested yet" in proc.stdout + proc.stderr

    def test_attestation_query_failure_fails_step(self, tmp_path):
        proc = self._run_attestation(
            tmp_path, {"docker": "#!/bin/sh\necho sha256:abc123\n", "gh": "#!/bin/sh\nexit 1\n"}
        )
        assert proc.returncode == 1
        assert "cannot verify" in proc.stdout + proc.stderr

    def test_attestation_verify_failure_fails_step(self, tmp_path):
        """The core tooth: a real verification failure must fail the step."""
        proc = self._run_attestation(
            tmp_path,
            {
                "docker": "#!/bin/sh\necho sha256:abc123\n",
                "gh": '#!/bin/sh\nif [ "$1" = "api" ]; then echo 1; else exit 1; fi\n',
            },
        )
        assert proc.returncode == 1
        assert "ceiling" not in proc.stdout + proc.stderr

    def test_attestation_verify_success_passes(self, tmp_path):
        proc = self._run_attestation(
            tmp_path,
            {
                "docker": "#!/bin/sh\necho sha256:abc123\n",
                "gh": '#!/bin/sh\nif [ "$1" = "api" ]; then echo 1; else exit 0; fi\n',
            },
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_no_echo_fallbacks_in_ci_gate_files(self):
        """The `|| echo <default>` green-blind class must not come back."""
        for rel in ("action.yml", "ci-templates/gitlab-picosentry.yml", ".github/workflows/verify-release.yml"):
            text = (_REPO_ROOT / rel).read_text()
            assert "|| echo" not in text, f"{rel} reintroduced an || echo fallback"


def _helm_deployment_template() -> str:
    return (_REPO_ROOT / "deploy" / "helm" / "picodome" / "templates" / "deployment.yaml").read_text()


def _render_args_block(grpc_enabled: bool) -> str:
    """Render the helm deployment container args with grpc toggled.

    The chart uses ``{{- if .Values.grpc.enabled }}`` around the grpc-only
    args. We emulate that by keeping the unconditional ``daemon --host --port``
    args and appending the grpc args only when ``grpc_enabled`` is True —
    mirroring the template's conditional, no helm binary needed.
    """
    template = _helm_deployment_template()
    assert "args:" in template, "deployment.yaml lost its args: block"
    # The unconditional block (daemon --host --port) must be present outside
    # any grpc conditional — that's the WO6.0.0-015 fix.
    assert re.search(
        r"^          args:\s*\n"
        r'            - "daemon"\s*\n'
        r'            - "--host={{ \.Values\.daemon\.host }}"\s*\n'
        r'            - "--port={{ \.Values\.daemon\.port }}"',
        template,
        re.MULTILINE,
    ), "deployment.yaml must emit `daemon --host --port` unconditionally (WO6.0.0-015)"
    base = [
        "daemon",
        "--host={{ .Values.daemon.host }}",
        "--port={{ .Values.daemon.port }}",
    ]
    if grpc_enabled:
        base.extend(["--transport=grpc", "--grpc-port={{ .Values.grpc.port }}"])
    return " ".join(base)


class TestHelmDefaultInstall:
    """The default ``helm install`` must start the daemon, not print --help
    and exit (WO6.0.0-015). The chart's args: block was conditional on
    grpc.enabled (default false), so the default render produced a pod with
    no args — Dockerfile CMD [--help] took over and the pod exited 0.
    """

    def test_default_render_carries_daemon_args(self):
        """grpc disabled (the default) must still pass `daemon --host --port`."""
        rendered = _render_args_block(grpc_enabled=False)
        assert "daemon" in rendered
        assert "--host={{ .Values.daemon.host }}" in rendered
        assert "--port={{ .Values.daemon.port }}" in rendered
        assert "--transport=grpc" not in rendered, "grpc args must not appear when grpc.enabled=false"

    def test_grpc_variant_adds_transport_grpc(self):
        """grpc.enabled=true appends --transport=grpc + --grpc-port."""
        rendered = _render_args_block(grpc_enabled=True)
        assert "daemon" in rendered
        assert "--transport=grpc" in rendered
        assert "--grpc-port={{ .Values.grpc.port }}" in rendered

    def test_no_grpc_only_conditional_around_args(self):
        """The args: block must NOT be wrapped in a grpc-only {{- if }} —
        that's the regression we're fixing. The grpc conditional may only
        wrap the grpc-specific args (--transport=grpc, --grpc-port)."""
        template = _helm_deployment_template()
        # The args: line must NOT be preceded by a grpc if-guard on the
        # previous non-blank line.
        lines = template.splitlines()
        for i, line in enumerate(lines):
            if line.strip() == "args:":
                # Walk back over blank lines to the nearest non-blank.
                j = i - 1
                while j >= 0 and not lines[j].strip():
                    j -= 1
                if j >= 0 and "grpc.enabled" in lines[j] and "{{- if" in lines[j]:
                    pytest.fail(
                        "args: block is wrapped in a grpc-only {{- if .Values.grpc.enabled }} — "
                        "default install prints --help and exits (WO6.0.0-015 regression)"
                    )
                break
        else:
            pytest.fail("no args: block found in deployment.yaml")


class TestAlertRunbookUrls:
    """Every runbook_url in picodome-alerts.yaml must point at the PicoSentry
    manual (ch. 13 anchors), not the wrong-repo 404s it carried before
    (WO6.0.0-021 item 6)."""

    @staticmethod
    def _runbook_urls() -> list[str]:
        import yaml

        text = (_REPO_ROOT / "deploy" / "monitoring" / "picodome-alerts.yaml").read_text()
        doc = yaml.safe_load(text)
        urls: list[str] = []
        for group in doc["spec"]["groups"]:
            for rule in group["rules"]:
                url = rule.get("annotations", {}).get("runbook_url")
                if url:
                    urls.append(url)
        return urls

    def test_all_runbooks_point_at_picosentry_manual(self):
        urls = self._runbook_urls()
        assert urls, "no runbook_url annotations found — test is stale"
        for url in urls:
            assert "KirkForge/PicoSentry/blob/main/docs/manual.md" in url, (
                f"runbook_url must point at PicoSentry manual, got: {url}"
            )
            assert "KirkForge/PicoDome" not in url, f"runbook_url still points at wrong repo: {url}"
            assert "docs/runbooks/" not in url, f"runbook_url still points at nonexistent tree: {url}"

    def test_runbook_anchors_resolve_in_manual(self):
        """Every #anchor in a runbook_url must match a heading in manual.md."""
        manual = (_REPO_ROOT / "docs" / "manual.md").read_text()
        # Collect all GitHub-style anchors from markdown headings.
        anchors: set[str] = set()
        for line in manual.splitlines():
            if line.startswith("#"):
                heading = line.lstrip("#").strip()
                anchor = re.sub(r"[^\w\s-]", "", heading).strip().lower().replace(" ", "-")
                anchors.add(anchor)
        for url in self._runbook_urls():
            anchor = url.split("#", 1)[1] if "#" in url else ""
            if not anchor:
                continue
            assert anchor in anchors, f"runbook anchor #{anchor} not found in manual.md headings"
