"""
Workspace / multi-project scanning for monorepos.

Discovers all projects (Node.js, Python, mixed) in a directory tree,
runs the sandbox on each project's test/install commands, and
aggregates results across the workspace.

Designed for enterprise pipelines where a single repo may contain
multiple packages (monorepo, pnpm workspace, Nx, etc.).
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from picosentry.sandbox.config import PicoDomeConfig, load_config
from picosentry.sandbox.l3.engine import sandbox_run
from picosentry.sandbox.l3.models import SandboxResult
from picosentry.sandbox.l4.engine import L4Engine, create_default_engine
from picosentry.sandbox.l4.models import AnalysisResult
from picosentry.sandbox.l4.profiler import profile_from_sandbox_result

logger = logging.getLogger("picodome.workspace")

# ── Project discovery patterns ────────────────────────────────────────────

# Files that indicate a project root
PROJECT_MARKERS = {
    "package.json": "node",
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "setup.py": "python",
    "Pipfile": "python",
    "poetry.lock": "python",
    "pnpm-workspace.yaml": "node",
    "lerna.json": "node",
    "nx.json": "node",
    "turbo.json": "node",
}

# Directories to skip during discovery
SKIP_DIRS = frozenset(
    {
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
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "site-packages",
        ".eggs",
        "eggs",
    }
)


class ProjectInfo:
    """Information about a discovered project."""

    def __init__(
        self,
        path: Path,
        project_type: str,
        name: str = "",
        version: str = "",
    ) -> None:
        self.path = path
        self.project_type = project_type
        self.name = name or path.name
        self.version = version

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "type": self.project_type,
            "name": self.name,
            "version": self.version,
        }


class WorkspaceResult:
    """Aggregated results from multi-project workspace scanning."""

    def __init__(self) -> None:
        self.projects: dict[str, ProjectInfo] = {}
        self.sandbox_results: dict[str, SandboxResult] = {}
        self.analysis_results: dict[str, AnalysisResult] = {}
        self.total_findings: int = 0
        self.total_projects: int = 0
        self.scanned_projects: int = 0
        self.failed_projects: int = 0
        self.errors: list[str] = []
        self.duration_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "total_projects": self.total_projects,
            "scanned_projects": self.scanned_projects,
            "failed_projects": self.failed_projects,
            "total_findings": self.total_findings,
            "duration_ms": self.duration_ms,
            "errors": self.errors,
            "projects": {k: v.to_dict() for k, v in self.projects.items()},
        }


def discover_projects(root: Path, max_depth: int = 8) -> list[ProjectInfo]:
    """Discover all projects in a directory tree.

    A project is any directory containing a recognized project marker
    (package.json, requirements.txt, pyproject.toml, etc.).

    Walks the tree up to max_depth, skipping known noise directories.
    Deduplicates by path (a directory with both package.json and
    pyproject.toml is counted once as 'mixed').

    Args:
        root: Root directory to scan.
        max_depth: Maximum directory depth from root to search.

    Returns:
        Sorted list of ProjectInfo objects.
    """
    if not root.is_dir():
        return []

    projects: dict[Path, ProjectInfo] = {}
    queue = [(root, 0)]

    while queue:
        current, depth = queue.pop(0)
        if depth > max_depth:
            continue

        try:
            entries = list(current.iterdir())
        except (PermissionError, OSError):
            continue

        names = {p.name for p in entries if p.is_file()}
        project_types = set()

        for marker, ptype in PROJECT_MARKERS.items():
            if marker in names:
                project_types.add(ptype)

        if project_types:
            # Determine project type (mixed if multiple)
            ptype = "mixed" if len(project_types) > 1 else project_types.pop()
            name = ""
            version = ""

            # Try to extract name/version from package.json
            pkg_json = current / "package.json"
            if pkg_json.is_file():
                try:
                    data = json.loads(pkg_json.read_text(encoding="utf-8"))
                    name = data.get("name", current.name)
                    version = data.get("version", "")
                except (json.JSONDecodeError, OSError):
                    name = current.name

            # Try pyproject.toml if no package.json name
            if not name:
                pyproject = current / "pyproject.toml"
                if pyproject.is_file():
                    try:
                        content = pyproject.read_text(encoding="utf-8")
                        for line in content.splitlines():
                            if line.strip().startswith("name"):
                                name = line.split("=", 1)[1].strip().strip('"').strip("'")
                                break
                    except OSError:
                        name = current.name

            if not name:
                name = current.name

            projects[current.resolve()] = ProjectInfo(
                path=current.resolve(),
                project_type=ptype,
                name=name,
                version=version,
            )

        # Recurse into subdirectories
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir() and entry.name not in SKIP_DIRS and not entry.name.startswith("."):
                queue.append((entry, depth + 1))

    return sorted(projects.values(), key=lambda p: str(p.path))


def _default_sandbox_commands(project: ProjectInfo) -> list[list[str]]:
    """Get default sandbox commands for a project type.

    Returns a list of command lists (each is argv-style).
    """
    if project.project_type == "node":
        return [
            ["npm", "install", "--dry-run"],
            ["npm", "test"],
        ]
    elif project.project_type == "python":
        return [
            ["pip", "install", "--dry-run", "."],
        ]
    elif project.project_type == "mixed":
        return [
            ["npm", "install", "--dry-run"],
            ["pip", "install", "--dry-run", "."],
        ]
    return []


def scan_workspace(
    root: Path,
    engine: L4Engine | None = None,
    config: PicoDomeConfig | None = None,
    commands: dict[str, list[list[str]]] | None = None,
    fail_on: str | None = None,
    timeout: float = 30.0,
) -> WorkspaceResult:
    """Scan an entire workspace for supply-chain issues.

    Discovers all projects in the directory tree, runs each through
    the L3 sandbox and L4 behavioral analysis, and aggregates results.

    Args:
        root: Root directory of the workspace.
        engine: Pre-configured L4 engine (created if None).
        config: PicoDome configuration (loaded if None).
        commands: Optional mapping of project path → list of commands.
            If not provided, default commands are used based on project type.
        fail_on: Minimum severity to consider a failure.
        timeout: Sandbox timeout in seconds per command.

    Returns:
        WorkspaceResult with aggregated findings and metadata.
    """
    if engine is None:
        engine = create_default_engine()

    if config is None:
        config = load_config(root)

    # Apply config overrides
    if config.timeout:
        timeout = config.timeout

    start = time.monotonic()

    # Discover projects
    projects = discover_projects(root)

    result = WorkspaceResult()
    result.total_projects = len(projects)

    logger.info("Discovered %d project(s) in workspace %s", len(projects), root)

    for project in projects:
        rel = project.path.relative_to(root) if str(project.path).startswith(str(root)) else project.path.name
        logger.info("Scanning: %s (%s)", rel, project.project_type)

        # Get sandbox commands
        project_commands = (
            commands.get(str(project.path), _default_sandbox_commands(project))
            if commands
            else _default_sandbox_commands(project)
        )

        if not project_commands:
            logger.info("  No commands for %s, skipping", rel)
            continue

        # Run sandbox for each command
        all_findings_count = 0
        project_ok = True

        for cmd in project_commands:
            try:
                # L3 sandbox
                sandbox_result = sandbox_run(
                    command=cmd,
                    timeout=timeout,
                    cwd=str(project.path),
                )

                # L4 behavioral analysis
                profile = profile_from_sandbox_result(sandbox_result)
                analysis = engine.analyze(profile)

                # Store results
                key = str(project.path)
                result.sandbox_results[f"{key}:{' '.join(cmd)}"] = sandbox_result
                result.analysis_results[f"{key}:{' '.join(cmd)}"] = analysis
                all_findings_count += len(analysis.findings)

                # Check fail threshold
                if fail_on and analysis.findings:
                    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
                    min_level = severity_order.get(fail_on.upper(), 2)
                    for f in analysis.findings:
                        if severity_order.get(f.severity.value, 4) <= min_level:
                            project_ok = False

                logger.info(
                    "  %s [%s]: %d finding(s), verdict=%s",
                    rel,
                    " ".join(cmd),
                    len(analysis.findings),
                    analysis.overall_verdict.value,
                )

            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                project_ok = False
                error_msg = f"{rel}: {e}"
                result.errors.append(error_msg)
                logger.error("  %s: FAILED — %s", rel, e)

        result.projects[str(project.path)] = project
        if project_ok:
            result.scanned_projects += 1
        else:
            result.failed_projects += 1
        result.total_findings += all_findings_count

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


def scan_workspace_to_json(
    root: Path,
    output: Path | None = None,
    **kwargs,
) -> str:
    """Scan workspace and return JSON string.

    Args:
        root: Root of the workspace.
        output: Optional file path to write results.
        **kwargs: Passed to scan_workspace().

    Returns:
        JSON string of aggregated results.
    """
    wr = scan_workspace(root, **kwargs)

    data = {
        "workspace_root": str(root.resolve()),
        "summary": wr.to_dict(),
        "sandbox_results": {k: v.to_dict() for k, v in wr.sandbox_results.items()},
        "analysis_results": {k: v.to_dict() for k, v in wr.analysis_results.items()},
    }

    json_str = json.dumps(data, indent=2, sort_keys=True, default=str)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json_str, encoding="utf-8")
        logger.info("Workspace results written to %s", output)

    return json_str
