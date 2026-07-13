from __future__ import annotations

import time
from pathlib import Path


_SKIP_DIRS = frozenset({".git", "__pycache__", ".cache", ".hg", ".svn", "node_modules/.cache"})

_RELEVANT_EXTENSIONS = frozenset(
    {
        ".json",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".yaml",
        ".yml",
        ".lock",
        ".npmrc",
        ".env",
        ".py",
        ".toml",
        ".cfg",
        ".ini",
        ".go",
        ".xml",
        ".gradle",
        ".rb",
        ".gemspec",
        ".csproj",
        ".sln",
    }
)

_RELEVANT_FILE_NAMES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    ".npmrc",
    "pnpm-workspace.yaml",
    "requirements.txt",
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "poetry.lock",
    "uv.lock",
    "Pipfile",
    "Pipfile.lock",
    "METADATA",
    "PKG-INFO",
    "go.mod",
    "go.sum",
    "go.env",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "Gemfile.lock",
    "packages.config",
    "packages.lock.json",
    "nuget.config",
}


def _now_ms() -> float:
    return time.monotonic() * 1000


def count_relevant_files(target_path: Path) -> int:
    """Return the number of files in ``target_path`` that are relevant to scans."""
    if target_path.is_file():
        return 1

    count = 0
    for file in target_path.rglob("*"):
        if not file.is_file() or file.is_symlink():
            continue
        if any(part in _SKIP_DIRS for part in file.parts):
            continue
        if file.suffix in _RELEVANT_EXTENSIONS or file.name in _RELEVANT_FILE_NAMES:
            count += 1
    return count


def count_installed_packages(target_path: Path) -> int:
    """Count installed dependencies under node_modules or .venv site-packages."""
    nm_path = target_path / "node_modules"
    if nm_path.is_dir():
        count = 0
        for d in nm_path.iterdir():
            if not d.is_dir() or d.name.startswith("."):
                continue
            if d.name.startswith("@"):
                count += sum(1 for s in d.iterdir() if s.is_dir())
            else:
                count += 1
        return count

    for sp_path in target_path.glob(".venv/lib/python*/site-packages"):
        if sp_path.is_dir():
            return sum(
                1 for d in sp_path.iterdir() if d.is_dir() and d.name.endswith((".dist-info", ".egg-info"))
            )
    return 0
