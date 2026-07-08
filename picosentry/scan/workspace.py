from __future__ import annotations

import logging
import multiprocessing
import time
from collections.abc import Sequence
from pathlib import Path

from picosentry.scan.config import PicoSentryConfig, load_config
from picosentry.scan.engine import ScanEngine, create_default_engine

logger = logging.getLogger("picosentry.workspace")


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

        names = {p.name for p in entries}
        if "package.json" in names:
            projects.add(current.resolve())

        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir() and entry.name not in SKIP_DIRS and not entry.name.startswith("."):
                queue.append((entry, depth + 1))

    return sorted(projects)


def discover_pnpm_workspace(root: Path) -> list[Path]:
    workspace_yaml = root / "pnpm-workspace.yaml"
    if not workspace_yaml.exists():
        return discover_projects(root)

    try:
        import yaml
    except ImportError:
        logger.warning("pyyaml not installed, falling back to generic discovery")
        return discover_projects(root)

    try:
        with workspace_yaml.open(encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except Exception:
        logger.warning("Failed to parse pnpm-workspace.yaml", exc_info=True)
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

            elif match.is_dir():
                pkg_json = match / "package.json"
                if pkg_json.exists():
                    projects.add(match.resolve())

    return sorted(projects) if projects else discover_projects(root)


class WorkspaceResult:
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
    try:
        from pathlib import Path as _Path

        from picosentry.scan.engine import create_default_engine as _cde

        _e = _cde(corpus_dir=_Path(corpus_dir) if corpus_dir else None, advisory_db_path=advisory_db_path)
        result_queue.put(("ok", _e.scan(target_path, rules=rules, advisory_db_path=advisory_db_path)))
    except (OSError, RuntimeError, ValueError, TypeError, TimeoutError) as exc:
        result_queue.put(("error", str(exc)))


def scan_workspace(
    root: Path,
    engine: ScanEngine | None = None,
    config: PicoSentryConfig | None = None,
    rules: Sequence[str] | None = None,
    timeout: int = 0,
) -> WorkspaceResult:
    if engine is None:
        engine = create_default_engine()

    if config is None:
        config = load_config(root)

    start = time.monotonic()

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

                    try:
                        while not _rq.empty():
                            _rq.get_nowait()
                    except (OSError, ValueError):
                        pass
                    _rq.close()
                    _rq.join_thread()
                    raise TimeoutError(f"scan of {rel} timed out after {timeout}s") from None
                try:
                    _st, scan_result = _rq.get(timeout=1)
                except (OSError, ValueError):
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
        except BaseException as e:
            result.failed_projects += 1
            error_msg = f"{rel}: {e}"
            result.errors.append(error_msg)
            logger.exception("  %s: FAILED", rel)

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
