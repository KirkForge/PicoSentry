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
        notes="Core scanner; 7 ecosystems; deterministic, offline; 54 rules, 1048 fixtures",
    ),
    ComponentStatus(
        name="`picosentry sandbox`",
        status="Stable",
        notes=(
            "seccomp-bpf enforces; gRPC + HTTP daemon; L4 behavioral analysis; "
            "seccomp-trace is opt-in and argument-limited"
        ),
    ),
    ComponentStatus(
        name="`picosentry watch`",
        status="Stable",
        notes=(
            "Deterministic regex + lexical classifier pre-filter for prompt injection (L5) "
            "and output validation (L6); not a semantic/LLM guarantee; CLI + HTTP server"
        ),
    ),
    ComponentStatus(
        name="`picosentry serve`",
        status="Beta",
        notes=(
            "API server, dashboard, RBAC, multi-tenant Postgres backend — security review + regression tests in place"
        ),
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
        status="Stable",
        notes="Export/import/validate/list/sign IoC packs; 3 built-in packs; deterministic signatures",
    ),
    ComponentStatus(
        name="Cross-layer correlation",
        status="Stable",
        notes=(
            "Links findings across scan + sandbox + watch layers; "
            "persistence, dedup, and per-minute backpressure tested in CI"
        ),
    ),
    ComponentStatus(
        name="Plugin system",
        status="Stable",
        notes=(
            "Loads, validates, dispatches; Ed25519 signature verify against a "
            "configured trusted-key allowlist; unsigned plugins load only when "
            "signing is not required"
        ),
    ),
    ComponentStatus(
        name="Postgres backend",
        status="Stable",
        notes=(
            "psycopg2 pool + runtime placeholder translation + DDL auto-translation + dialect helpers; live PG 15/16 CI"
        ),
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
        notes="1048 fixtures (899 pos / 142 neg), 54 rules, 94.44% prec, 73.79% recall — see docs/model-card.md",
    ),
    ComponentStatus(
        name="Docker image",
        status="Stable",
        notes="`kirkforge/picodome:v2.0.18` on Docker Hub; multi-arch (linux/amd64 + linux/arm64); non-root user",
    ),
    ComponentStatus(
        name="PyPI package",
        status="Stable",
        notes="`pip install picosentry` — v2.0.18 published",
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
