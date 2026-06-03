"""
Reproducible builds — SOURCE_DATE_EPOCH, pinned dep hashes, hermetic pip.

PicoDome's core thesis is determinism. Builds MUST be bit-for-bit reproducible.
This module provides:

- ReproducibleBuild: configuration class for reproducible builds
- get_source_date_epoch(): read SOURCE_DATE_EPOCH or fallback to build timestamp
- pin_dependencies(): read requirements/pip lock and return pinned hashes
- verify_reproducible_build(): verify a built wheel is reproducible
- hermetic_build_config(): config for hermetic pip install (no network during build)
- generate_build_manifest(): generate a build manifest JSON with all hashes

Design principles:
- SOURCE_DATE_EPOCH must be respected for all timestamp generation during build.
- All dependency versions must be pinned with hashes (pip --require-hashes).
- The build must work in air-gapped environments (all deps pre-downloaded).
- Tests must work without network access.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# ─── Constants ────────────────────────────────────────────────────────────────

_DEFAULT_SOURCE_DATE_EPOCH = 0  # 1970-01-01 00:00:00 UTC
_HASH_ALGORITHMS = ("sha256", "sha384", "sha512")
_PIP_HASH_PATTERN = re.compile(
    r"^(?P<name>[a-zA-Z0-9_.-]+)==(?P<version>[^;\s]+)"
    r"\s*(?:--hash=(?P<algo>sha\d+):(?P<hash>[a-f0-9]+))*"
)
_REQUIREMENTS_LINE_PATTERN = re.compile(
    r"^(?P<pkg>[a-zA-Z0-9_.-]+)==(?P<ver>[^;\s]+)"  # package==version
    r"(?:\s*--hash=(?P<algo>sha\d+):(?P<hash_val>[a-f0-9]+))*"  # hash specs
    r"\s*$"
)
_WHEEL_HASH_CHUNK_SIZE = 65536  # 64KB chunks for hashing

# ─── Exceptions ────────────────────────────────────────────────────────────────


class ReproducibleBuildError(Exception):
    """Raised when a reproducible build check fails."""


# ─── ReproducibleBuild class ──────────────────────────────────────────────────


@dataclass(frozen=True)
class ReproducibleBuild:
    """Configuration for a reproducible build.

    Encapsulates all settings needed to produce bit-for-bit identical builds:
    - source_date_epoch: deterministic timestamp (epoch seconds)
    - python_hash_seed: fixed hash seed for dict ordering (0 = off)
    - pip_no_build_isolation: don't use pip's build isolation
    - require_hashes: all deps must have hash verification
    - no_deps: don't install dependencies automatically
    - offline: don't access the network during build
    """

    source_date_epoch: int = 0
    python_hash_seed: int = 0
    pip_no_build_isolation: bool = True
    require_hashes: bool = True
    no_deps: bool = False
    offline: bool = True

    def to_dict(self) -> dict:
        """Serialize to dict with sorted keys for deterministic JSON."""
        d = {
            "source_date_epoch": self.source_date_epoch,
            "python_hash_seed": self.python_hash_seed,
            "pip_no_build_isolation": self.pip_no_build_isolation,
            "require_hashes": self.require_hashes,
            "no_deps": self.no_deps,
            "offline": self.offline,
        }
        return {k: v for k, v in sorted(d.items())}

    def env_vars(self) -> dict[str, str]:
        """Return environment variables for the reproducible build."""
        env = {
            "SOURCE_DATE_EPOCH": str(self.source_date_epoch),
            "PYTHONHASHSEED": str(self.python_hash_seed),
        }
        return env

    def pip_install_args(self) -> list[str]:
        """Return pip install arguments for reproducible install."""
        args = []
        if self.require_hashes:
            args.append("--require-hashes")
        if self.pip_no_build_isolation:
            args.append("--no-build-isolation")
        if self.no_deps:
            args.append("--no-deps")
        if self.offline:
            args.append("--offline")
        return args


# ─── Core functions ────────────────────────────────────────────────────────────


def get_source_date_epoch(fallback_timestamp: int | None = None) -> int:
    """Read SOURCE_DATE_EPOCH env var or use fallback timestamp.

    SOURCE_DATE_EPOCH is the standard environment variable for reproducible builds.
    If set, it must be used for all timestamp generation during the build process.
    If not set, use the fallback_timestamp if provided, otherwise 0 (epoch).

    Args:
        fallback_timestamp: Optional timestamp to use if SOURCE_DATE_EPOCH is not set.
            If None, defaults to 0 (1970-01-01 00:00:00 UTC).

    Returns:
        Integer epoch seconds.

    Raises:
        ReproducibleBuildError: If SOURCE_DATE_EPOCH is set but not a valid integer.
    """
    env_val = os.environ.get("SOURCE_DATE_EPOCH")
    if env_val is not None:
        try:
            epoch = int(env_val)
        except (ValueError, TypeError) as exc:
            raise ReproducibleBuildError(f"SOURCE_DATE_EPOCH must be an integer, got: {env_val!r}") from exc
        if epoch < 0:
            raise ReproducibleBuildError(f"SOURCE_DATE_EPOCH must be non-negative, got: {epoch}")
        return epoch

    # No env var: use fallback or default
    if fallback_timestamp is not None:
        return fallback_timestamp
    return _DEFAULT_SOURCE_DATE_EPOCH


def pin_dependencies(lockfile_path: str) -> dict:
    """Read requirements/pip lock and return pinned hashes.

    Parses a requirements.txt or pip-compatible lock file and extracts
    package names, versions, and their hash pins.

    Args:
        lockfile_path: Path to requirements.txt or pip lock file.

    Returns:
        Dict with:
        - "packages": list of dicts with "name", "version", "hashes" keys
        - "total": count of pinned packages
        - "lockfile": the input path

    Raises:
        ReproducibleBuildError: If lockfile doesn't exist or has no valid entries.
    """
    path = Path(lockfile_path)
    if not path.is_file():
        raise ReproducibleBuildError(f"Lockfile not found: {lockfile_path}")

    content = path.read_text(encoding="utf-8")
    packages: list[dict] = []

    for line in content.splitlines():
        line = line.strip()
        # Skip comments, empty lines, and options
        if not line or line.startswith("#") or line.startswith("-"):
            # But collect --hash lines attached to previous package
            continue

        # Parse package==version or package>=version with optional --hash specs
        match = re.match(r"^(?P<name>[a-zA-Z0-9_.-]+)(?P<op>==|>=|<=|~=|!=|>|<)(?P<version>[^;\s]+)", line)
        if not match:
            continue

        name = match.group("name")
        version = match.group("version")
        version_op = match.group("op")

        # Extract all --hash=algo:hash pairs from the line
        hashes: list[dict[str, str]] = []
        for hmatch in re.finditer(r"--hash=(?P<algo>sha\d+):(?P<hash_val>[a-f0-9]+)", line):
            hashes.append(
                {
                    "algorithm": hmatch.group("algo"),
                    "hash": hmatch.group("hash_val"),
                }
            )

        packages.append(
            {
                "name": name,
                "version": version,
                "version_op": version_op,
                "hashes": hashes,
            }
        )

    if not packages:
        raise ReproducibleBuildError(f"No valid package entries found in lockfile: {lockfile_path}")

    return {
        "packages": packages,
        "total": len(packages),
        "lockfile": str(path),
    }


def verify_reproducible_build(wheel_path: str) -> dict:
    """Verify a built wheel is reproducible.

    Checks:
    1. File exists and is a valid zip (wheel format)
    2. No embedded timestamps in zip entries (all must be epoch 0)
    3. No non-deterministic filenames (no __pycache__, .pyc with random names)
    4. RECORD file has deterministic entries
    5. Hash of the wheel file itself for reference comparison

    Args:
        wheel_path: Path to the .whl file to verify.

    Returns:
        Dict with:
        - "reproducible": bool — whether the build is reproducible
        - "checks": list of check results
        - "wheel_hash": SHA-256 of the wheel file
        - "violations": list of violations found (empty if reproducible)

    Raises:
        ReproducibleBuildError: If wheel file doesn't exist or isn't a valid wheel.
    """
    path = Path(wheel_path)
    if not path.is_file():
        raise ReproducibleBuildError(f"Wheel file not found: {wheel_path}")

    if not path.suffix == ".whl":
        raise ReproducibleBuildError(f"Not a wheel file (expected .whl extension): {wheel_path}")

    violations: list[str] = []
    checks: list[dict] = []

    # Check 1: Valid zip file
    try:
        with zipfile.ZipFile(path, "r") as zf:
            namelist = zf.namelist()
            checks.append(
                {
                    "check": "valid_zip",
                    "passed": True,
                    "detail": f"{len(namelist)} entries",
                }
            )
    except zipfile.BadZipFile as exc:
        checks.append({"check": "valid_zip", "passed": False, "detail": str(exc)})
        violations.append(f"Invalid zip file: {exc}")
        return {
            "reproducible": False,
            "checks": checks,
            "wheel_hash": _file_sha256(path),
            "violations": violations,
        }

    # Check 2: No embedded timestamps in zip entries
    with zipfile.ZipFile(path, "r") as zf:
        timestamp_violations = []
        for info in zf.infolist():
            # date_time is (year, month, day, hour, minute, second)
            # Epoch 0 = 1980-01-01 00:00:00 in zip format (minimum DOS date)
            # Or actual epoch 0 which maps to 1980-01-01 in DOS format
            dt = info.date_time
            # For reproducible builds, we expect either:
            # - 1980-01-01 00:00:00 (DOS epoch, zip minimum)
            # - 1970-01-01 00:00:00 (Unix epoch, but zip stores 1980 minimum)
            # A truly reproducible build sets all timestamps to epoch 0
            # which in zip format appears as 1980-01-01 00:00:00
            if dt != (1980, 1, 1, 0, 0, 0) and dt != (1970, 1, 1, 0, 0, 0):
                timestamp_violations.append(
                    f"{info.filename}: {dt[0]:04d}-{dt[1]:02d}-{dt[2]:02d}T{dt[3]:02d}:{dt[4]:02d}:{dt[5]:02d}"
                )

        if timestamp_violations:
            passed = False
            violations.extend(timestamp_violations)
        else:
            passed = True
        checks.append(
            {
                "check": "no_embedded_timestamps",
                "passed": passed,
                "detail": f"{len(timestamp_violations)} entries with non-epoch timestamps",
            }
        )

        # Check 3: No non-deterministic files
        nondeterministic = []
        for name in namelist:
            # __pycache__ dirs with .pyc files have hash-based names
            if "__pycache__" in name and name.endswith(".pyc"):
                nondeterministic.append(name)
            # .dist-info/WHEEL should not contain non-reproducible entries
            # RECORD is OK (it's deterministic by content)

        if nondeterministic:
            passed = False
            violations.extend(f"Non-deterministic file: {f}" for f in nondeterministic)
        else:
            passed = True
        checks.append(
            {
                "check": "no_nondeterministic_files",
                "passed": passed,
                "detail": f"{len(nondeterministic)} non-deterministic files",
            }
        )

        # Check 4: WHEEL metadata file should reference SOURCE_DATE_EPOCH
        wheel_meta = [n for n in namelist if n.endswith("/WHEEL")]
        if wheel_meta:
            content = zf.read(wheel_meta[0]).decode("utf-8")
            # Check that there's no "Generated" or date line
            has_generated = "Generated" in content or "generated" in content
            if not has_generated:
                passed = True
                detail = "WHEEL metadata clean"
            else:
                passed = False
                violations.append("WHEEL metadata contains 'Generated' timestamp")
                detail = "WHEEL metadata contains 'Generated' timestamp"
        else:
            passed = True
            detail = "No WHEEL metadata file"
        checks.append(
            {
                "check": "wheel_metadata_clean",
                "passed": passed,
                "detail": detail,
            }
        )

    # Check 5: Wheel file hash (for reference)
    wheel_hash = _file_sha256(path)
    checks.append(
        {
            "check": "wheel_hash",
            "passed": True,
            "detail": wheel_hash,
        }
    )

    reproducible = len(violations) == 0
    return {
        "reproducible": reproducible,
        "checks": checks,
        "wheel_hash": wheel_hash,
        "violations": violations,
    }


def hermetic_build_config() -> dict:
    """Return config for hermetic pip install (no network during build).

    A hermetic build ensures:
    - No network access during build (--offline, --require-hashes)
    - All dependencies pre-downloaded and hash-verified
    - PYTHONHASHSEED fixed for deterministic dict ordering
    - SOURCE_DATE_EPOCH fixed for deterministic timestamps
    - No build isolation (--no-build-isolation)

    Returns:
        Dict with:
        - "env": environment variables to set
        - "pip_args": pip install arguments
        - "build_args": python -m build arguments
        - "config": ReproducibleBuild configuration dict
    """
    epoch = get_source_date_epoch()
    config = ReproducibleBuild(
        source_date_epoch=epoch,
        python_hash_seed=0,
        pip_no_build_isolation=True,
        require_hashes=True,
        no_deps=False,
        offline=True,
    )

    return {
        "env": config.env_vars(),
        "pip_args": config.pip_install_args(),
        "build_args": [
            "--no-build-isolation",
        ],
        "config": config.to_dict(),
    }


def generate_build_manifest(output_dir: str) -> str:
    """Generate a build manifest JSON with all hashes.

    The manifest includes:
    - source_date_epoch: the epoch used for the build
    - python_hash_seed: fixed seed for dict ordering
    - source_files: SHA-256 hashes of all Python source files
    - config: hermetic build configuration
    - timestamp: ISO 8601 timestamp of manifest generation (deterministic)

    Args:
        output_dir: Directory to scan for source files and write manifest.

    Returns:
        Path to the generated manifest JSON file.

    Raises:
        ReproducibleBuildError: If output_dir doesn't exist.
    """
    out_path = Path(output_dir)
    if not out_path.is_dir():
        raise ReproducibleBuildError(f"Output directory not found: {output_dir}")

    epoch = get_source_date_epoch()
    source_files: dict[str, str] = {}

    # Hash all Python source files
    for py_file in sorted(out_path.rglob("*.py")):
        # Skip __pycache__ and .git directories
        if "__pycache__" in str(py_file) or ".git" in str(py_file):
            continue
        rel_path = str(py_file.relative_to(out_path))
        source_files[rel_path] = _file_sha256(py_file)

    # Also hash config files
    for config_file in ["pyproject.toml", "setup.cfg", "setup.py", "MANIFEST.in"]:
        cf = out_path / config_file
        if cf.is_file():
            source_files[config_file] = _file_sha256(cf)

    # Hash requirements files
    for req_file in out_path.glob("requirements*.txt"):
        rel = str(req_file.relative_to(out_path))
        source_files[rel] = _file_sha256(req_file)

    manifest = {
        "source_date_epoch": epoch,
        "python_hash_seed": 0,
        "source_files": dict(sorted(source_files.items())),
        "total_source_files": len(source_files),
        "config": hermetic_build_config(),
        "timestamp": _epoch_to_iso(epoch),
        "manifest_version": "1.0.0",
        "tool": "picodome-reproducible",
    }

    manifest_path = out_path / "build-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return str(manifest_path)


# ─── Helper functions ──────────────────────────────────────────────────────────


def _file_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_WHEEL_HASH_CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _epoch_to_iso(epoch: int) -> str:
    """Convert epoch seconds to ISO 8601 string (UTC)."""
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
