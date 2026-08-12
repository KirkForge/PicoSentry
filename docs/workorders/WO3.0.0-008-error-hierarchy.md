# WO3.0.0-008 — Unified Exception Hierarchy + Bare-Except Cleanup

**Series:** WO3.0.0 (improvement loop)
**Status:** OPEN
**Owner:** subagent (worktree `wo/3.0.0/error-hierarchy`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/serve/ -m "not slow"`

## Objective
Define a unified serve-wide exception hierarchy and reduce the 62 bare `except Exception` across 36 files to explicit catches.

## Root cause being addressed
Error handling 7/10: `picosentry/serve/errors.py` has error *constants* (`ServeError`, `ServeErrors`) but no exception base class. 62 bare `except Exception` hides bugs and swallows KeyboardInterrupt/SystemExit.

## Scope
- `picosentry/serve/errors.py` — add a `PicoSentryError(Exception)` base + typed subclasses (e.g. `AuthError`, `ValidationError`, `ServiceError`, `NotFoundError`)
- Convert bare `except Exception` to `except SpecificError` where the error type is known; keep `except Exception` only where truly appropriate (with a comment)
- Global exception handler in `server.py` maps the new hierarchy to HTTP status codes
- Do NOT touch the `ponytail:`-documented best-effort paths (rate-limit_redis) unless the workorder asks

## Done-condition
- Unified exception hierarchy exists
- Most bare `except Exception` reduced to explicit catches (target: <20 remain, documented)
- HTTP error mapping works
- All gates green

## Notes
- Do NOT rewrite tests to pass.
- Preserve honest-doc annotations.
