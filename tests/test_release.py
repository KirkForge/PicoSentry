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
