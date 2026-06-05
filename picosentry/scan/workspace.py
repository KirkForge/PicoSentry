"""
Workspace / multi-project scanning for monorepos.

Scans entire monorepo by discovering all npm/pnpm projects,
running each through the scanner, and aggregating results.

Designed for enterprise pipelines where a single repo may contain
hundreds of packages (e.g., Nx, Turborepo, Lerna, pnpm workspaces).
"""

from __future__ import annotations

import json
import logging
import multiprocessing
import time
from collections.abc import Sequence
from pathlib import Path

from picosentry.scan.config import PicoSentryConfig, load_config
from picosentry.scan.engine import ScanEngine, create_default_engine

logger = logging.getLogger("picosentry.workspace")

# Glob patterns for project discovery
NPM_MANIFEST_GLOBS = [
    "**/package.json",
    "**/pnpm-lock.yaml",
    "**/package-lock.json",
    "**/yarn.lock",
    "**/pnpm-workspace.yaml",
    "**/nx.json",
    "**/lerna.json",
    "**/turbo.json",
]
# Directories to skip during discovery
SKIP_DIRS = {
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    "coverage",
    ".nyc_output",
}


def discover_projects(root: Path, max_depth: int = 8) -> list[Path]:
    """Discover all npm/pnpm projects in a directory tree.

    A project is any directory containing a package.json or lockfile.
    Walks the tree up to max_depth, skipping known noise directories.

    Args:
        root: Root directory to scan.
        max_depth: Maximum directory depth from root to search.

    Returns:
        Sorted list of project directories (deduplicated).
    """
    if not root.is_dir():
        return []

    projects: set[Path] = set()
    queue = [(root, 0)]

    while queue:
        current, depth = queue.pop(0)
        if depth > max_depth:
            continue

        try:
            entries = list(current.iterdir())
        except (PermissionError, OSError):
            continue

        # Check if this directory is a project
        names = {p.name for p in entries}
        if "package.json" in names:
            projects.add(current.resolve())

        # Recurse into subdirectories (skip symlinks to avoid traversal outside root)
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir() and entry.name not in SKIP_DIRS and not entry.name.startswith("."):
                queue.append((entry, depth + 1))

    return sorted(projects)


def discover_pnpm_workspace(root: Path) -> list[Path]:
    """Discover projects from a pnpm workspace definition.

    Reads pnpm-workspace.yaml and returns all workspace member directories.
    Falls back to generic discovery if no workspace config found.

    Args:
        root: Root of the monorepo.

    Returns:
        Sorted list of resolved project directories.
    """
    workspace_yaml = root / "pnpm-workspace.yaml"
    if not workspace_yaml.exists():
        return discover_projects(root)

    try:
        import yaml
    except ImportError:
        logger.warning("pyyaml not installed, falling back to generic discovery")
        return discover_projects(root)

    try:
        with open(workspace_yaml, encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except Exception as e:
        logger.warning("Failed to parse pnpm-workspace.yaml: %s", e)
        return discover_projects(root)

    if not isinstance(config, dict):
        return discover_projects(root)

    packages = config.get("packages", [])
    if not packages:
        return discover_projects(root)

    projects: set[Path] = set()
    for pattern in packages:
        matches = list(root.glob(pattern))
        for match in matches:
            if match.is_symlink():
                continue  # Skip symlinks to avoid traversal outside root
            if match.is_dir() and (match / "package.json").exists():
                projects.add(match.resolve())

            # If the glob matched a directory that contains package.json deeper
            elif match.is_dir():
                pkg_json = match / "package.json"
                if pkg_json.exists():
                    projects.add(match.resolve())

    return sorted(projects) if projects else discover_projects(root)


class WorkspaceResult:
    """Aggregated results from multi-project scanning."""

    def __init__(self) -> None:
        self.results: dict[str, object] = {}  # project_path -> ScanResult
        self.total_findings = 0
        self.total_projects = 0
        self.scanned_projects = 0
        self.failed_projects = 0
        self.errors: list[str] = []
        self.duration_ms = 0

    def to_dict(self) -> dict:
        return {
            "total_projects": self.total_projects,
            "scanned_projects": self.scanned_projects,
            "failed_projects": self.failed_projects,
            "total_findings": self.total_findings,
            "duration_ms": self.duration_ms,
            "errors": self.errors,
        }


def _workspace_scan_worker(
    target_path: str,
    rules: list[str] | None,
    corpus_dir: str | None,
    advisory_db_path: str | None,
    result_queue: multiprocessing.Queue,
) -> None:
    """Module-level worker for workspace project scans (picklable for spawn start method)."""
    try:
        from pathlib import Path as _Path

        from picosentry.scan.engine import create_default_engine as _cde

        _e = _cde(corpus_dir=_Path(corpus_dir) if corpus_dir else None, advisory_db_path=advisory_db_path)
        result_queue.put(("ok", _e.scan(target_path, rules=rules, advisory_db_path=advisory_db_path)))
    except Exception as exc:
        result_queue.put(("error", str(exc)))


def scan_workspace(
    root: Path,
    engine: ScanEngine | None = None,
    config: PicoSentryConfig | None = None,
    rules: Sequence[str] | None = None,
    fail_on: str = "medium",
    timeout: int = 0,
) -> WorkspaceResult:
    """Scan an entire monorepo workspace.

    Discovers all npm/pnpm projects, scans each one, aggregates results.
    Supports pnpm workspaces, Nx, Turborepo, Lerna layouts.

    Args:
        root: Root of the monorepo.
        engine: Pre-configured engine (created if None).
        config: PicoSentry configuration (loaded if None).
        rules: Specific rule IDs to run (all if None).
        fail_on: Minimum severity to fail CI on.
        timeout: Per-project timeout in seconds (0 = none).

    Returns:
        WorkspaceResult with aggregated findings and metadata.
    """
    if engine is None:
        engine = create_default_engine()

    if config is None:
        config = load_config(root)

    start = time.monotonic()

    # Discover projects
    projects = discover_pnpm_workspace(root)
    if not projects:
        projects = discover_projects(root)

    result = WorkspaceResult()
    result.total_projects = len(projects)

    logger.info("Discovered %d project(s) in workspace", len(projects))

    for project_path in projects:
        rel = project_path.relative_to(root) if project_path.is_relative_to(root) else project_path.name
        logger.info("Scanning: %s", rel)

        try:
            if timeout and timeout > 0:
                import multiprocessing as _mp

                _rq: _mp.Queue = _mp.Queue()

                _p = _mp.Process(
                    target=_workspace_scan_worker,
                    args=(
                        str(project_path),
                        list(rules) if rules else None,
                        str(engine._corpus_dir) if engine._corpus_dir else None,
                        getattr(engine, "_advisory_db_path", None) or None,
                        _rq,
                    ),
                )
                _p.start()
                _p.join(timeout=timeout)
                if _p.is_alive():
                    _p.terminate()
                    _p.join(timeout=1)
                    # Drain the queue to release resources held by the worker
                    try:
                        while not _rq.empty():
                            _rq.get_nowait()
                    except Exception:
                        pass
                    _rq.close()
                    _rq.join_thread()
                    raise TimeoutError(f"scan of {rel} timed out after {timeout}s") from None
                try:
                    _st, scan_result = _rq.get(timeout=1)
                except Exception:
                    raise TimeoutError(f"scan of {rel} timed out after {timeout}s") from None
                finally:
                    _rq.close()
                    _rq.join_thread()
                if _st == "error":
                    raise RuntimeError(scan_result)
            else:
                scan_result = engine.scan(
                    str(project_path),
                    rules=list(rules) if rules else None,
                )
            # Apply config-based filtering to scan result
            if config:
                if config.severity_overrides:
                    scan_result.apply_overrides(config.apply_severity_overrides(scan_result.findings))
                if config.ignore_packages or config.ignore_paths:
                    scan_result.apply_overrides(
                        [
                            f
                            for f in scan_result.findings
                            if not config.should_ignore_package(f.package) and not config.should_ignore_path(f.file)
                        ]
                    )
                from picosentry.scan.models import SEVERITY_ORDER
                if config.severity_threshold:
                    threshold = config.severity_threshold
                    min_level = SEVERITY_ORDER[threshold.lower()]
                    scan_result.apply_overrides(
                        [
                            f
                            for f in scan_result.findings
                            if SEVERITY_ORDER.get(f.severity.value.lower(), 4) <= min_level
                        ]
                    )
            result.results[str(project_path)] = scan_result.to_dict()
            result.scanned_projects += 1
            result.total_findings += len(scan_result.findings)

            logger.info(
                "  %s: %d finding(s) in %dms",
                rel,
                len(scan_result.findings),
                scan_result.stats.duration_ms,
            )
        except Exception as e:
            result.failed_projects += 1
            error_msg = f"{rel}: {e}"
            result.errors.append(error_msg)
            logger.error("  %s: FAILED — %s", rel, e)

    result.duration_ms = int((time.monotonic() - start) * 1000)

    logger.info(
        "Workspace scan complete: %d/%d projects, %d findings, %d failed, %dms",
        result.scanned_projects,
        result.total_projects,
        result.total_findings,
        result.failed_projects,
        result.duration_ms,
    )

    return result


def scan_workspace_to_json(root: Path, output: Path | None = None, **kwargs) -> str:
    """Scan workspace and return JSON string.

    Args:
        root: Root of the monorepo.
        output: Optional file path to write results.
        **kwargs: Passed to scan_workspace().

    Returns:
        JSON string of aggregated results.
    """
    wr = scan_workspace(root, **kwargs)

    data = {
        "workspace_root": str(root.resolve()),
        "summary": wr.to_dict(),
        "projects": wr.results,
    }

    json_str = json.dumps(data, indent=2, sort_keys=True)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json_str, encoding="utf-8")
        logger.info("Workspace results written to %s", output)

    return json_str
