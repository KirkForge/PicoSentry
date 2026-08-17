# WO2.0.0-003 — Improve Error Handling

**Series:** WO2.0.0 (improvement loop)
**Status:** UNVERIFIED (spec predates status tracking; series reported COMPLETE — verify scope before reopening)
**Owner:** subagent (worktree `wo/2.0.0/error-handling`)
**Gate:** `uv run pytest tests/ -m "not slow"` + `uv run ruff check` + `uv run mypy picosentry/`

## Objective
Improve error handling across the codebase: consistent, actionable, non-leaky errors at trust boundaries.

## Scope
- Audit exception handling in `picosentry/serve/` (FastAPI error paths) and `picosentry/scan/` (network/parse errors).
- Ensure API error responses never leak internal details (stack traces, SQL, file paths) to clients.
- Verify `response_model=None` convention on endpoints that return `JSONResponse` (per AGENTS.md permanent convention).
- Ensure subprocess/sandbox failures produce clear, structured errors.
- Add an ADR for the serve orchestration API (currently a GAP — no ADR exists).

## Root cause being addressed
Inconsistent error handling produces either silent failures or information-leaking responses.

## Done-condition
- No API error path leaks internals.
- All error paths return structured, actionable errors.
- New ADR documents the serve orchestration API.

## Notes
- Do NOT add debug logging to committed code.
- Do NOT rewrite tests to pass.
- Preserve honest-doc annotations.
