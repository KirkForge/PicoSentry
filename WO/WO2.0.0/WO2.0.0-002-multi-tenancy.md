# WO2.0.0-002 — Build Out Multi-Tenancy

**Series:** WO2.0.0 (improvement loop)
**Status:** OPEN
**Owner:** subagent (worktree `wo/2.0.0/multi-tenancy`)
**Gate:** `uv run pytest tests/ -m "not slow"` + `uv run ruff check` + `uv run mypy picosentry/`

## Objective
Complete and harden the multi-tenancy / org-isolation model in the serve orchestration API.

## Context
The codebase already has tenant/org scaffolding:
- `picosentry/sandbox/tenant/store.py` — `TenantAwareScanJobStore`, `DEFAULT_TENANT`, `TenantId`
- `picosentry/serve/api/routers/orgs.py` + `tenant.py` — org gating
- `get_current_org` dependency on scan/sandbox/admin endpoints

## Scope
- Audit every serve API router for consistent org scoping (no cross-tenant data leaks).
- Verify `get_current_org` is applied to ALL data-bearing endpoints, not just some.
- Confirm tenant isolation in the DB layer (queries scoped by org_id).
- Add an ADR for the multi-tenancy model (currently a GAP — no ADR exists).

## Root cause being addressed
Multi-tenancy is partially implemented; inconsistent org gating is a cross-tenant data-leak risk.

## Done-condition
- Every data-bearing serve endpoint is org-scoped.
- No endpoint returns another tenant's data.
- New ADR documents the isolation model.

## Notes
- Do NOT rewrite tests to pass. Fix the root cause (missing org gating).
- Preserve honest-doc annotations (`ponytail:`, `ceiling:`, `upgrade path:`).
