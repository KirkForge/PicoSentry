"""
Tests for reproducible builds — SOURCE_DATE_EPOCH, pinned dep hashes, hermetic pip.

These tests MUST work without network access.
"""

import hashlib
import json
import os
import zipfile
from pathlib import Path
from unittest import mock

import pytest

from picosentry.sandbox.reproducible import (
    ReproducibleBuild,
    ReproducibleBuildError,
    _epoch_to_iso,
    _file_sha256,
    generate_build_manifest,
    get_source_date_epoch,
    hermetic_build_config,
    pin_dependencies,
    verify_reproducible_build,
)

# ─── Test fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture
def sample_requirements(tmp_path):
    """Create a sample requirements.txt with hash-pinned dependencies."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "# PicoDome pinned requirements\n"
        "setuptools>=68.0 --hash=sha256:a:b\n"
        "wheel==0.42.0 --hash=sha256:abc123def456\n"
        "pyyaml>=6.0 --hash=sha256:xyz789\n"
        "\n"
        "# Dev dependencies\n"
        "pytest>=7.0 --hash=sha256:pytest7hash\n"
        "ruff>=0.8 --hash=sha256:ruff08hash\n",
        encoding="utf-8",
    )
    return str(req_file)


@pytest.fixture
def sample_requirements_no_hashes(tmp_path):
    """Create a requirements.txt without hash pins."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "setuptools>=68.0\nwheel==0.42.0\npytest>=7.0\n",
        encoding="utf-8",
    )
    return str(req_file)


@pytest.fixture
def sample_wheel(tmp_path):
    """Create a minimal valid .whl file for testing."""
    wheel_path = tmp_path / "picodome-0.3.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel_path, "w") as zf:
        # Use epoch timestamp (1980-01-01 in DOS format = zip minimum)
        info = zipfile.ZipInfo("picodome/__init__.py", date_time=(1980, 1, 1, 0, 0, 0))
        zf.writestr(info, '__version__ = "0.3.0"\n')
        # Add WHEEL metadata without Generated timestamp
        info2 = zipfile.ZipInfo("picodome-0.3.0.dist-info/WHEEL", date_time=(1980, 1, 1, 0, 0, 0))
        zf.writestr(info2, "Wheel-Version: 1.0\nRoot-Is-Purelib: true\n")
        # Add METADATA
        info3 = zipfile.ZipInfo("picodome-0.3.0.dist-info/METADATA", date_time=(1980, 1, 1, 0, 0, 0))
        zf.writestr(info3, "Metadata-Version: 2.1\nName: picodome\nVersion: 0.3.0\n")
    return str(wheel_path)


@pytest.fixture
def sample_wheel_with_timestamps(tmp_path):
    """Create a .whl file with non-epoch timestamps (non-reproducible)."""
    wheel_path = tmp_path / "picodome-0.3.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel_path, "w") as zf:
        # Non-epoch timestamp (2025-06-15 10:30:00)
        info = zipfile.ZipInfo("picodome/__init__.py", date_time=(2025, 6, 15, 10, 30, 0))
        zf.writestr(info, '__version__ = "0.3.0"\n')
    return str(wheel_path)


@pytest.fixture
def source_dir(tmp_path):
    """Create a minimal source directory for manifest generation."""
    src = tmp_path / "src" / "picodome"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text('__version__ = "0.3.0"\n', encoding="utf-8")
    (src / "reproducible.py").write_text("# reproducible builds\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[build-system]\n", encoding="utf-8")
    return str(tmp_path)


# ─── get_source_date_epoch tests ───────────────────────────────────────────────


class TestGetSourceDateEpoch:
    """Tests for get_source_date_epoch()."""

    def test_reads_env_var(self):
        """SOURCE_DATE_EPOCH env var should be read and returned as int."""
        with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1700000000"}):
            assert get_source_date_epoch() == 1700000000

    def test_reads_env_var_zero(self):
        """SOURCE_DATE_EPOCH=0 should return 0 (Unix epoch)."""
        with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "0"}):
            assert get_source_date_epoch() == 0

    def test_default_without_env_var(self):
        """Without env var and no fallback, should return 0."""
        with mock.patch.dict(os.environ, {}, clear=True):
            # Remove SOURCE_DATE_EPOCH if it exists
            os.environ.pop("SOURCE_DATE_EPOCH", None)
            assert get_source_date_epoch() == 0

    def test_fallback_timestamp(self):
        """Without env var, fallback_timestamp should be used."""
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("SOURCE_DATE_EPOCH", None)
            assert get_source_date_epoch(fallback_timestamp=1700000000) == 1700000000

    def test_env_var_takes_precedence_over_fallback(self):
        """SOURCE_DATE_EPOCH env var should take precedence over fallback."""
        with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "999"}):
            assert get_source_date_epoch(fallback_timestamp=1700000000) == 999

    def test_invalid_env_var_raises(self):
        """Non-integer SOURCE_DATE_EPOCH should raise ReproducibleBuildError."""
        with (
            mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "not-a-number"}),
            pytest.raises(ReproducibleBuildError, match="must be an integer"),
        ):
            get_source_date_epoch()

    def test_negative_env_var_raises(self):
        """Negative SOURCE_DATE_EPOCH should raise ReproducibleBuildError."""
        with (
            mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "-1"}),
            pytest.raises(ReproducibleBuildError, match="non-negative"),
        ):
            get_source_date_epoch()


# ─── pin_dependencies tests ───────────────────────────────────────────────────


class TestPinDependencies:
    """Tests for pin_dependencies()."""

    def test_parses_hash_pinned_requirements(self, sample_requirements):
        """Should parse requirements with --hash pins."""
        result = pin_dependencies(sample_requirements)
        assert result["total"] == 5
        assert result["lockfile"] == sample_requirements

        # Check setuptools entry
        setuptools = [p for p in result["packages"] if p["name"] == "setuptools"]
        assert len(setuptools) == 1
        assert setuptools[0]["version"] == "68.0"
        assert setuptools[0]["version_op"] == ">="

    def test_extracts_hashes(self, sample_requirements):
        """Should extract --hash=algo:hash pairs."""
        result = pin_dependencies(sample_requirements)
        wheel_pkg = next(p for p in result["packages"] if p["name"] == "wheel")
        assert len(wheel_pkg["hashes"]) == 1
        assert wheel_pkg["hashes"][0]["algorithm"] == "sha256"
        assert wheel_pkg["hashes"][0]["hash"] == "abc123def456"

    def test_packages_without_hashes(self, sample_requirements_no_hashes):
        """Should parse packages even without --hash pins."""
        result = pin_dependencies(sample_requirements_no_hashes)
        assert result["total"] == 3
        for pkg in result["packages"]:
            assert pkg["hashes"] == []
            # version_op should be captured
            assert pkg["version_op"] in ("==", ">=", "<=", "~=", "!=", ">", "<")

    def test_missing_lockfile_raises(self, tmp_path):
        """Should raise ReproducibleBuildError for missing file."""
        fake_path = str(tmp_path / "nonexistent.txt")
        with pytest.raises(ReproducibleBuildError, match="not found"):
            pin_dependencies(fake_path)

    def test_empty_lockfile_raises(self, tmp_path):
        """Should raise ReproducibleBuildError for empty file."""
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("# just comments\n\n", encoding="utf-8")
        with pytest.raises(ReproducibleBuildError, match="No valid package entries"):
            pin_dependencies(str(empty_file))

    def test_skips_comments_and_options(self, tmp_path):
        """Should skip comment lines and option lines."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            "# This is a comment\n"
            "-i https://pypi.org/simple\n"
            "--extra-index-url https://example.com\n"
            "requests==2.31.0 --hash=sha256:abc\n",
            encoding="utf-8",
        )
        result = pin_dependencies(str(req_file))
        assert result["total"] == 1
        assert result["packages"][0]["name"] == "requests"


# ─── verify_reproducible_build tests ──────────────────────────────────────────


class TestVerifyReproducibleBuild:
    """Tests for verify_reproducible_build()."""

    def test_valid_reproducible_wheel(self, sample_wheel):
        """A wheel with epoch timestamps should pass verification."""
        result = verify_reproducible_build(sample_wheel)
        assert result["reproducible"] is True
        assert len(result["violations"]) == 0
        assert "wheel_hash" in result
        assert len(result["wheel_hash"]) == 64  # SHA-256 hex

    def test_wheel_with_timestamps_fails(self, sample_wheel_with_timestamps):
        """A wheel with non-epoch timestamps should fail verification."""
        result = verify_reproducible_build(sample_wheel_with_timestamps)
        assert result["reproducible"] is False
        assert len(result["violations"]) > 0
        # Should find timestamp violations
        ts_violations = [v for v in result["violations"] if "2025" in v]
        assert len(ts_violations) > 0

    def test_missing_wheel_raises(self, tmp_path):
        """Should raise ReproducibleBuildError for missing file."""
        with pytest.raises(ReproducibleBuildError, match="not found"):
            verify_reproducible_build(str(tmp_path / "missing.whl"))

    def test_non_wheel_raises(self, tmp_path):
        """Should raise ReproducibleBuildError for non-.whl file."""
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("not a wheel", encoding="utf-8")
        with pytest.raises(ReproducibleBuildError, match="Not a wheel file"):
            verify_reproducible_build(str(txt_file))

    def test_checks_include_valid_zip(self, sample_wheel):
        """Result should include valid_zip check."""
        result = verify_reproducible_build(sample_wheel)
        checks = {c["check"]: c for c in result["checks"]}
        assert "valid_zip" in checks
        assert checks["valid_zip"]["passed"] is True

    def test_checks_include_timestamp_check(self, sample_wheel):
        """Result should include no_embedded_timestamps check."""
        result = verify_reproducible_build(sample_wheel)
        checks = {c["check"]: c for c in result["checks"]}
        assert "no_embedded_timestamps" in checks
        assert checks["no_embedded_timestamps"]["passed"] is True

    def test_checks_include_wheel_hash(self, sample_wheel):
        """Result should include wheel_hash check."""
        result = verify_reproducible_build(sample_wheel)
        checks = {c["check"]: c for c in result["checks"]}
        assert "wheel_hash" in checks
        assert checks["wheel_hash"]["passed"] is True


# ─── hermetic_build_config tests ──────────────────────────────────────────────


class TestHermeticBuildConfig:
    """Tests for hermetic_build_config()."""

    def test_returns_env_vars(self):
        """Should return environment variables for hermetic build."""
        with mock.patch.dict(os.environ, {}, clear=True):
            os.environ.pop("SOURCE_DATE_EPOCH", None)
            config = hermetic_build_config()
        assert "SOURCE_DATE_EPOCH" in config["env"]
        assert "PYTHONHASHSEED" in config["env"]
        assert config["env"]["PYTHONHASHSEED"] == "0"

    def test_returns_pip_args(self):
        """Should return pip arguments for hermetic install."""
        with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1700000000"}):
            config = hermetic_build_config()
        assert "--require-hashes" in config["pip_args"]
        assert "--no-build-isolation" in config["pip_args"]
        assert "--offline" in config["pip_args"]

    def test_returns_build_args(self):
        """Should return build arguments."""
        with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1700000000"}):
            config = hermetic_build_config()
        assert "--no-build-isolation" in config["build_args"]

    def test_respects_source_date_epoch(self):
        """Should use SOURCE_DATE_EPOCH from env if set."""
        with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1700000000"}):
            config = hermetic_build_config()
        assert config["config"]["source_date_epoch"] == 1700000000

    def test_config_is_serializable(self):
        """Config should be JSON-serializable."""
        with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1700000000"}):
            config = hermetic_build_config()
        # Should not raise
        json_str = json.dumps(config, sort_keys=True)
        assert "source_date_epoch" in json_str


# ─── ReproducibleBuild class tests ────────────────────────────────────────────


class TestReproducibleBuild:
    """Tests for ReproducibleBuild dataclass."""

    def test_default_values(self):
        """Default config should be fully hermetic."""
        rb = ReproducibleBuild()
        assert rb.source_date_epoch == 0
        assert rb.python_hash_seed == 0
        assert rb.pip_no_build_isolation is True
        assert rb.require_hashes is True
        assert rb.no_deps is False
        assert rb.offline is True

    def test_to_dict_sorted_keys(self):
        """to_dict() should return sorted keys."""
        rb = ReproducibleBuild(source_date_epoch=1700000000)
        d = rb.to_dict()
        assert list(d.keys()) == sorted(d.keys())

    def test_env_vars(self):
        """env_vars() should return correct environment variables."""
        rb = ReproducibleBuild(source_date_epoch=1700000000, python_hash_seed=42)
        env = rb.env_vars()
        assert env["SOURCE_DATE_EPOCH"] == "1700000000"
        assert env["PYTHONHASHSEED"] == "42"

    def test_pip_install_args(self):
        """pip_install_args() should return correct pip flags."""
        rb = ReproducibleBuild()
        args = rb.pip_install_args()
        assert "--require-hashes" in args
        assert "--no-build-isolation" in args
        assert "--offline" in args
        assert "--no-deps" not in args  # no_deps defaults to False

    def test_pip_install_args_no_deps(self):
        """pip_install_args() should include --no-deps when configured."""
        rb = ReproducibleBuild(no_deps=True)
        args = rb.pip_install_args()
        assert "--no-deps" in args

    def test_frozen(self):
        """ReproducibleBuild should be frozen (immutable)."""
        rb = ReproducibleBuild()
        with pytest.raises(AttributeError):
            rb.source_date_epoch = 999


# ─── generate_build_manifest tests ─────────────────────────────────────────────


class TestGenerateBuildManifest:
    """Tests for generate_build_manifest()."""

    def test_generates_manifest_file(self, source_dir):
        """Should generate a build-manifest.json file."""
        manifest_path = generate_build_manifest(source_dir)
        assert Path(manifest_path).exists()
        assert Path(manifest_path).name == "build-manifest.json"

    def test_manifest_contains_source_files(self, source_dir):
        """Manifest should list hashed source files."""
        manifest_path = generate_build_manifest(source_dir)
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        assert "source_files" in manifest
        assert manifest["total_source_files"] > 0
        # Should have __init__.py
        init_files = [k for k in manifest["source_files"] if "__init__.py" in k]
        assert len(init_files) > 0

    def test_manifest_contains_config(self, source_dir):
        """Manifest should contain hermetic build config."""
        manifest_path = generate_build_manifest(source_dir)
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        assert "config" in manifest
        assert "python_hash_seed" in manifest
        assert manifest["python_hash_seed"] == 0

    def test_manifest_is_deterministic(self, source_dir):
        """Running manifest generation twice should produce identical output."""
        path1 = generate_build_manifest(source_dir)
        content1 = Path(path1).read_text(encoding="utf-8")
        path2 = generate_build_manifest(source_dir)
        content2 = Path(path2).read_text(encoding="utf-8")
        assert content1 == content2

    def test_manifest_with_source_date_epoch(self, source_dir):
        """Manifest should respect SOURCE_DATE_EPOCH env var."""
        with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1700000000"}):
            manifest_path = generate_build_manifest(source_dir)
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)
        assert manifest["source_date_epoch"] == 1700000000

    def test_missing_dir_raises(self, tmp_path):
        """Should raise ReproducibleBuildError for missing directory."""
        fake_dir = str(tmp_path / "nonexistent")
        with pytest.raises(ReproducibleBuildError, match="not found"):
            generate_build_manifest(fake_dir)


# ─── Helper function tests ────────────────────────────────────────────────────


class TestHelpers:
    """Tests for helper functions."""

    def test_file_sha256(self, tmp_path):
        """_file_sha256 should compute correct SHA-256 hash."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world", encoding="utf-8")
        # SHA-256 of "hello world"
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert _file_sha256(test_file) == expected

    def test_file_sha256_empty(self, tmp_path):
        """_file_sha256 should handle empty files."""
        test_file = tmp_path / "empty.txt"
        test_file.write_bytes(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert _file_sha256(test_file) == expected

    def test_epoch_to_iso_zero(self):
        """_epoch_to_iso(0) should return 1970-01-01T00:00:00Z."""
        assert _epoch_to_iso(0) == "1970-01-01T00:00:00Z"

    def test_epoch_to_iso_known_date(self):
        """_epoch_to_iso should convert known epoch correctly."""
        # 2024-01-01 00:00:00 UTC = 1704067200
        result = _epoch_to_iso(1704067200)
        assert result.startswith("2024-01-01T00:00:00Z")

    def test_epoch_to_iso_deterministic(self):
        """Same epoch should always produce same ISO string."""
        epoch = 1700000000
        assert _epoch_to_iso(epoch) == _epoch_to_iso(epoch)
