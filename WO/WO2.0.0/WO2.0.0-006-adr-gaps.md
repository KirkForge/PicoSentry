# WO2.0.0-006 — ADR Gap: Multi-Tenancy + Serve Orchestration + LLM Watch

**Series:** WO2.0.0 (improvement loop)
**Status:** OPEN
**Owner:** subagent (worktree `wo/2.0.0/adr-gaps`)
**Gate:** `uv run ruff check` + `uv run mypy picosentry/`

## Objective
Write new ADRs for three major architectural decisions that currently have NO ADR:
1. **Multi-tenancy / org isolation** — `picosentry/sandbox/tenant/store.py`, `picosentry/serve/api/routers/orgs.py` + `tenant.py`.
2. **Serve orchestration API** — `picosentry/serve/services/orchestrator.py` + the full `serve/api/routers/` surface.
3. **LLM watch subsystem** — `picosentry/watch/` (prompt guard, output guard, telemetry/OTel, ratelimit, server).

## Deliverables
- `docs/adr/ADR-007-multi-tenancy.md`
- `docs/adr/ADR-008-serve-orchestration-api.md`
- `docs/adr/ADR-009-llm-watch.md`

## Done-condition
- ADR-007, ADR-008, ADR-009 exist and accurately describe the implementations.
