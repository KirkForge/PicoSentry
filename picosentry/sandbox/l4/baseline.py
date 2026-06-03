"""L4 baseline management — known-good behavioral profiles."""

from __future__ import annotations

import json
from pathlib import Path

from picosentry.sandbox.l4.models import Baseline

# Shipped baselines for common packages
SHIPPED_BASELINES: dict[str, Baseline] = {
    "npm-install": Baseline(
        name="npm-install",
        package="npm",
        version="*",
        expected_network_calls=10,
        expected_dns_queries=5,
        expected_fs_ops=500,
        expected_spawns=0,
        expected_runtime_ms_range=(1000, 120000),
        allowed_domains=["registry.npmjs.org", "registry.yarnpkg.com"],
        allowed_paths=["node_modules/**", "package.json", "package-lock.json"],
        notes="Default npm install baseline — allows registry access and node_modules writes",
    ),
    "python-pip-install": Baseline(
        name="python-pip-install",
        package="pip",
        version="*",
        expected_network_calls=5,
        expected_dns_queries=3,
        expected_fs_ops=200,
        expected_spawns=0,
        expected_runtime_ms_range=(500, 60000),
        allowed_domains=["pypi.org", "files.pythonhosted.org"],
        allowed_paths=["**/site-packages/**", "/tmp/**"],
        notes="Default pip install baseline",
    ),
    "node-script": Baseline(
        name="node-script",
        package="node",
        version="*",
        expected_network_calls=1,
        expected_dns_queries=1,
        expected_fs_ops=50,
        expected_spawns=0,
        expected_runtime_ms_range=(10, 30000),
        allowed_domains=["localhost"],
        allowed_paths=["**"],
        notes="Generic Node.js script execution — allows local filesystem, denies external network",
    ),
    "python-script": Baseline(
        name="python-script",
        package="python",
        version="*",
        expected_network_calls=0,
        expected_dns_queries=0,
        expected_fs_ops=100,
        expected_spawns=0,
        expected_runtime_ms_range=(10, 30000),
        allowed_domains=[],
        allowed_paths=["**"],
        notes="Generic Python script execution — no network, local filesystem only",
    ),
    "curl-wget": Baseline(
        name="curl-wget",
        package="curl",
        version="*",
        expected_network_calls=1,
        expected_dns_queries=1,
        expected_fs_ops=10,
        expected_spawns=0,
        expected_runtime_ms_range=(100, 60000),
        allowed_domains=["*"],
        allowed_paths=["/dev/null", "/tmp/**"],
        notes="curl/wget download — allows any domain, writes to /tmp only",
    ),
}


def load_baseline(name: str) -> Baseline | None:
    """Load a specific baseline by name."""
    return SHIPPED_BASELINES.get(name)


def load_all_baselines() -> dict[str, Baseline]:
    """Load all shipped baselines. Can be extended with custom baselines."""
    return dict(SHIPPED_BASELINES)


def register_baseline(baseline: Baseline) -> None:
    """Register a custom baseline at runtime."""
    SHIPPED_BASELINES[baseline.name] = baseline


def load_baselines_from_path(path: Path) -> dict[str, Baseline]:
    """Load custom baselines from a JSON file."""
    with open(path) as f:
        data = json.load(f)

    baselines: dict[str, Baseline] = {}
    for entry in data:
        b = Baseline(
            name=entry["name"],
            package=entry.get("package", entry["name"]),
            version=entry.get("version", ""),
            expected_network_calls=entry.get("expected_network_calls", 0),
            expected_dns_queries=entry.get("expected_dns_queries", 0),
            expected_fs_ops=entry.get("expected_fs_ops", 0),
            expected_spawns=entry.get("expected_spawns", 0),
            expected_runtime_ms_range=tuple(entry.get("expected_runtime_ms_range", [0, 0])),
            allowed_domains=entry.get("allowed_domains", []),
            allowed_paths=entry.get("allowed_paths", []),
            notes=entry.get("notes", ""),
        )
        baselines[b.name] = b

    return baselines
