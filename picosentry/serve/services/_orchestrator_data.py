import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

# Optional psycopg2 support for health-check probe error classification.
try:
    import psycopg2
except ImportError:
    psycopg2 = cast("Any", None)

# Expected failures when probing external dependencies in health checks.
# A probe failure must be reported as degraded, not crash the health endpoint.
_HEALTH_PROBE_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    sqlite3.Error,
)
if psycopg2 is not None:
    _HEALTH_PROBE_ERRORS = (*_HEALTH_PROBE_ERRORS, psycopg2.Error)

BASE_DIR = Path(__file__).parent.parent
REGISTRY_PATH = BASE_DIR / "config" / "project_registry.json"

PICO_CLI: dict[str, list[str]] = {
    "picosentry": ["picosentry", "scan"],
    "picodome": ["picosentry", "sandbox", "run"],
    "picowatch": ["picosentry", "watch", "scan-prompt"],
    "picoshogun": ["picosentry", "health"],
}

PROJECT_LAYER_MAP: dict[str, str] = {
    "picosentry": "scan",
    "picodome": "sandbox_l3",
    "picowatch": "watch",
}

# Strict allowlist for project IDs and package names that are fed into
# subprocess.run().  Anything outside [A-Za-z0-9_.-] is rejected to prevent
# shell metacharacters, path traversal, or unexpected executable resolution.
_PROJECT_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")
_PACKAGE_NAME_RE = re.compile(r"^[a-zA-Z0-9_.-]+$")


def _validate_project_command(project_id: str, package: str) -> None:
    """Raise ValueError if project_id or package can reach unsafe executables."""
    if not _PROJECT_ID_RE.match(project_id):
        raise ValueError(f"Project ID {project_id!r} contains unsafe characters")
    if package and not _PACKAGE_NAME_RE.match(package):
        raise ValueError(f"Package name {package!r} contains unsafe characters")


def _load_registry(path: Path) -> dict[str, "ProjectMeta"]:
    registry: dict[str, ProjectMeta] = {}
    if not path.exists():
        return registry
    try:
        with path.open() as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        # A corrupt or unreadable registry must not silently produce an empty
        # project list. The caller is responsible for logging; we just return
        # the empty registry so startup remains visible.
        return registry
    for pid, pdict in data.items():
        try:
            registry[pid] = ProjectMeta(**pdict)
        except (TypeError, ValueError):
            continue
    return registry


@dataclass
class ProjectMeta:
    id: str
    name: str
    category: str
    priority: int
    dependencies: list[str]
    cron_schedule: str
    estimated_duration: int
    status: str = "pending"
    version: str = "1.0.1"
    intelligence_outputs: list[str] | None = None
    intelligence_inputs: list[str] | None = None
    description: str = ""
    package: str = ""
