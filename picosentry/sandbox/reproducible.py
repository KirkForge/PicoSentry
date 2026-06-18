
from __future__ import annotations

import hashlib
import json
import os
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


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


class ReproducibleBuildError(Exception):
    """Raised when a reproducible build check fails."""


@dataclass(frozen=True)
class ReproducibleBuild:

    source_date_epoch: int = 0
    python_hash_seed: int = 0
    pip_no_build_isolation: bool = True
    require_hashes: bool = True
    no_deps: bool = False
    offline: bool = True

    def to_dict(self) -> dict:
        d = {
            "source_date_epoch": self.source_date_epoch,
            "python_hash_seed": self.python_hash_seed,
            "pip_no_build_isolation": self.pip_no_build_isolation,
            "require_hashes": self.require_hashes,
            "no_deps": self.no_deps,
            "offline": self.offline,
        }
        return dict(sorted(d.items()))

    def env_vars(self) -> dict[str, str]:
        return {
            "SOURCE_DATE_EPOCH": str(self.source_date_epoch),
            "PYTHONHASHSEED": str(self.python_hash_seed),
        }

    def pip_install_args(self) -> list[str]:
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


def get_source_date_epoch(fallback_timestamp: int | None = None) -> int:
    env_val = os.environ.get("SOURCE_DATE_EPOCH")
    if env_val is not None:
        try:
            epoch = int(env_val)
        except (ValueError, TypeError) as exc:
            raise ReproducibleBuildError(f"SOURCE_DATE_EPOCH must be an integer, got: {env_val!r}") from exc
        if epoch < 0:
            raise ReproducibleBuildError(f"SOURCE_DATE_EPOCH must be non-negative, got: {epoch}")
        return epoch


    if fallback_timestamp is not None:
        return fallback_timestamp
    return _DEFAULT_SOURCE_DATE_EPOCH


def pin_dependencies(lockfile_path: str) -> dict:
    path = Path(lockfile_path)
    if not path.is_file():
        raise ReproducibleBuildError(f"Lockfile not found: {lockfile_path}")

    content = path.read_text(encoding="utf-8")
    packages: list[dict] = []

    for line in content.splitlines():
        line = line.strip()

        if not line or line.startswith(("#", "-")):

            continue


        match = re.match(r"^(?P<name>[a-zA-Z0-9_.-]+)(?P<op>==|>=|<=|~=|!=|>|<)(?P<version>[^;\s]+)", line)
        if not match:
            continue

        name = match.group("name")
        version = match.group("version")
        version_op = match.group("op")


        hashes = [
            {
                "algorithm": hmatch.group("algo"),
                "hash": hmatch.group("hash_val"),
            }
            for hmatch in re.finditer(r"--hash=(?P<algo>sha\d+):(?P<hash_val>[a-f0-9]+)", line)
        ]

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
    path = Path(wheel_path)
    if not path.is_file():
        raise ReproducibleBuildError(f"Wheel file not found: {wheel_path}")

    if not path.suffix == ".whl":
        raise ReproducibleBuildError(f"Not a wheel file (expected .whl extension): {wheel_path}")

    violations: list[str] = []
    checks: list[dict] = []


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


    with zipfile.ZipFile(path, "r") as zf:
        timestamp_violations = []
        for info in zf.infolist():


            dt = info.date_time


            if dt not in ((1980, 1, 1, 0, 0, 0), (1970, 1, 1, 0, 0, 0)):
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


        nondeterministic = [
            name
            for name in namelist
            if "__pycache__" in name and name.endswith(".pyc")
        ]


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


        wheel_meta = [n for n in namelist if n.endswith("/WHEEL")]
        if wheel_meta:
            content = zf.read(wheel_meta[0]).decode("utf-8")

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
    out_path = Path(output_dir)
    if not out_path.is_dir():
        raise ReproducibleBuildError(f"Output directory not found: {output_dir}")

    epoch = get_source_date_epoch()
    source_files: dict[str, str] = {}


    for py_file in sorted(out_path.rglob("*.py")):

        if "__pycache__" in str(py_file) or ".git" in str(py_file):
            continue
        rel_path = str(py_file.relative_to(out_path))
        source_files[rel_path] = _file_sha256(py_file)


    for config_file in ["pyproject.toml", "setup.cfg", "setup.py", "MANIFEST.in"]:
        cf = out_path / config_file
        if cf.is_file():
            source_files[config_file] = _file_sha256(cf)


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


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_WHEEL_HASH_CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _epoch_to_iso(epoch: int) -> str:
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
