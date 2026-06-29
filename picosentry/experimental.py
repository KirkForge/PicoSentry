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
        notes="Core scanner; 7 ecosystems; deterministic, offline; 54 rules, 188 fixtures",
    ),
    ComponentStatus(
        name="`picosentry sandbox`",
        status="Beta",
        notes="seccomp-bpf enforces; gRPC + HTTP daemon; L4 behavioral analysis",
    ),
    ComponentStatus(
        name="`picosentry watch`",
        status="Beta",
        notes=(
            "Deterministic regex + lexical classifier pre-filter for prompt injection (L5) "
            "and output validation (L6); not a semantic/LLM guarantee; CLI + HTTP server"
        ),
    ),
    ComponentStatus(
        name="`picosentry serve`",
        status="Beta",
        notes="API server, dashboard, RBAC, multi-tenant — security review + regression tests in place",
    ),
    ComponentStatus(
        name="`picosentry daemon`",
        status="Beta",
        notes="Sandbox-as-a-service; HTTP + gRPC; auth, rate limiting, TLS/mTLS, audit",
    ),
    ComponentStatus(
        name="`picosentry admission`",
        status="Beta",
        notes=(
            "K8s admission webhook; pod security validation + optional image scanning; "
            "fail-closed by default when image scanning is enabled; live-tested against a kind cluster"
        ),
    ),
    ComponentStatus(
        name="`picosentry corpus`",
        status="Beta",
        notes="Export/import/validate/list/sign IoC packs; 3 built-in packs",
    ),
    ComponentStatus(
        name="Cross-layer correlation",
        status="Beta",
        notes=(
            "Links findings across scan + sandbox + watch layers; "
            "persistence, dedup, and per-minute backpressure tested"
        ),
    ),
    ComponentStatus(
        name="Plugin system",
        status="Beta",
        notes=(
            "Loads, validates, dispatches; Ed25519 signature verify against a "
            "configured trusted-key allowlist; unsigned plugins load only when "
            "signing is not required"
        ),
    ),
    ComponentStatus(
        name="Postgres backend",
        status="Beta",
        notes="psycopg2 pool + runtime placeholder translation + DDL auto-translation + dialect helpers",
    ),
    ComponentStatus(
        name="Cluster mode",
        status="Beta",
        notes=(
            "Gossip over HTTP(S) with shared cluster token + optional mTLS; "
            "monotonic versioning; 3-node integration test"
        ),
    ),
    ComponentStatus(
        name="Detection benchmarks",
        status="Stable",
        notes="188 fixtures (150 pos / 38 neg), 54 rules, 100% CI floor (small corpus — see honest limitations)",
    ),
    ComponentStatus(
        name="Docker image",
        status="Stable",
        notes="`kirkforge/picodome:v2.0.17` on Docker Hub; multi-arch (linux/amd64 + linux/arm64); non-root user",
    ),
    ComponentStatus(
        name="PyPI package",
        status="Stable",
        notes="`pip install picosentry` — v2.0.17 published",
    ),
)


def render_status_table() -> str:
    """Render the component status table as GitHub-flavored markdown."""
    lines = [
        "| Component | Status | Notes |",
        "|-----------|--------|-------|",
    ]
    lines.extend(f"| {component.name} | **{component.status}** | {component.notes} |" for component in COMPONENT_STATUS)
    return "\n".join(lines)


__all__ = [
    "COMPONENT_STATUS",
    "ComponentStatus",
    "Status",
    "render_status_table",
]
