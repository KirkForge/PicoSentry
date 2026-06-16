
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Status = Literal["Stable", "Beta", "Experimental"]


@dataclass(frozen=True)
class ComponentStatus:
    """Machine-readable entry for the README status table."""

    name: str
    status: Status
    notes: str


# Source of truth for the component maturity table in README.md.
# The ``name`` and ``notes`` strings are stored exactly as they appear in the
# README markdown table (including backticks), so ``render_status_table()``
# produces a byte-for-byte match.
COMPONENT_STATUS: tuple[ComponentStatus, ...] = (
    ComponentStatus(
        name="`picosentry scan`",
        status="Stable",
        notes="Core scanner; 7 ecosystems; deterministic, offline; 53 rules, 178 fixtures",
    ),
    ComponentStatus(
        name="`picosentry sandbox`",
        status="Beta",
        notes="seccomp-bpf enforces; gRPC + HTTP daemon; L4 behavioral analysis",
    ),
    ComponentStatus(
        name="`picosentry watch`",
        status="Beta",
        notes="Prompt-injection detection (L5) + output validation (L6); CLI + HTTP server",
    ),
    ComponentStatus(
        name="`picosentry serve`",
        status="Experimental",
        notes="API server, dashboard, RBAC, multi-tenant — not reviewed for untrusted networks",
    ),
    ComponentStatus(
        name="`picosentry daemon`",
        status="Beta",
        notes="Sandbox-as-a-service; HTTP + gRPC; auth, rate limiting, TLS/mTLS, audit",
    ),
    ComponentStatus(
        name="`picosentry admission`",
        status="Beta",
        notes="K8s admission webhook; pod security validation + optional image scanning",
    ),
    ComponentStatus(
        name="`picosentry corpus`",
        status="Beta",
        notes="Export/import/validate/list/sign IoC packs; 3 built-in packs",
    ),
    ComponentStatus(
        name="Cross-layer correlation",
        status="Experimental",
        notes="Links findings across scan + sandbox + watch layers",
    ),
    ComponentStatus(
        name="Plugin system",
        status="Beta",
        notes="Loads, validates, dispatches; Ed25519 signature verify; PicoShogun protocol",
    ),
    ComponentStatus(
        name="Postgres backend",
        status="Beta",
        notes="psycopg2 implementation done; migrations are SQLite DDL — needs separate PG schema",
    ),
    ComponentStatus(
        name="Cluster mode",
        status="Experimental",
        notes="Gossip HTTP endpoints + periodic auto-sync loop; 7+ multi-node tests pass",
    ),
    ComponentStatus(
        name="Detection benchmarks",
        status="Stable",
        notes="178 fixtures (145 pos / 33 neg), 53 rules, 100% CI floor (small corpus — see honest limitations)",
    ),
    ComponentStatus(
        name="Docker image",
        status="Stable",
        notes="`kirkforge/picodome:v2.0.13` on Docker Hub; all 4 components healthy; non-root user",
    ),
    ComponentStatus(
        name="PyPI package",
        status="Stable",
        notes="`pip install picosentry` — v2.0.13 published",
    ),
)


def render_status_table() -> str:
    """Render the component status table as GitHub-flavored markdown."""
    lines = [
        "| Component | Status | Notes |",
        "|-----------|--------|-------|",
    ]
    for component in COMPONENT_STATUS:
        lines.append(
            f"| {component.name} | **{component.status}** | {component.notes} |"
        )
    return "\n".join(lines)


__all__ = [
    "COMPONENT_STATUS",
    "ComponentStatus",
    "Status",
    "render_status_table",
]
