# ADR-008: Serve orchestration API

**Status:** Accepted
**Date:** 2026-08

## Context

The `picosentry/serve` package exposes a FastAPI orchestration surface that
drives the offline scanner, sandbox, correlation engine, and alerting. The
orchestration core lives in `picosentry/serve/services/orchestrator.py`
(`EnhancedOrchestrator`), which owns the project registry, subprocess
execution, intelligence extraction, correlation, and alert dispatch. The HTTP
layer in `picosentry/serve/api/routers/` (projects, health, dashboard,
scans, correlation, scheduler, webhooks, orgs, auth, admin, metrics) maps
those operations to REST endpoints.

No ADR documented this API's shape, error contract, or trust boundaries.
This ADR records the intended contract so future changes (and the error
handling work in WO2.0.0-003) have a stable reference.

## Decision

### Orchestration core (`EnhancedOrchestrator`)

- **Synchronous, thread-bound.** `run_project` / `run_batch` execute
  subprocesses synchronously under a semaphore
  (`settings.orchestrator.max_concurrent_projects`). The HTTP layer bridges
  to the async event loop with `asyncio.to_thread` (see `projects.py`).
- **Result dicts, not exceptions.** `run_project` returns a dict. Success is
  `{"success": True, "duration", "output", "stderr", "intelligence_count"}`.
  Failure paths return `{"error": <sanitized>, "duration"}` — never a raw
  exception. The only exception that escapes is `ValueError` from
  `_validate_project_command` / unsafe-CLI-arg checks, which the router maps
  to a 400.
- **Sanitized error strings.** The generic execution-failure path
  (`RuntimeError`/`OSError`/`ValueError`/`TypeError`) returns the constant
  `"project execution failed"` to callers; the real exception is logged with
  `logger.exception`. Raw `str(e)` is never returned to the HTTP layer.
- **Subprocess contract.** `subprocess.run(..., capture_output=True,
  text=True, timeout=timeout, check=False)` — no shell, no `check=True`.
  `TimeoutExpired` is a distinct, structured `{"error": "timeout"}` result.
  Exit codes are recorded in `project_runs` and surfaced as
  `success: returncode == 0`.

### HTTP layer

- **Endpoints return Pydantic models or plain dicts.** Where an endpoint can
  return a `JSONResponse` (error path) alongside a dict (happy path), the
  decorator MUST set `response_model=None` (AGENTS.md permanent convention).
  This prevents `FastAPIError` at route registration and avoids the latent
  bug of a `JSONResponse` being re-serialized through a declared model.
- **Errors are `HTTPException` with fixed detail strings.** Routers map
  domain failures to 400/403/404/500 with a constant, non-leaking detail.
  Raw exception messages, SQL, file paths, and stack traces never reach the
  client body.
- **Auth failures are generic.** `get_current_user` returns 401
  "Invalid or expired token"; `get_current_org` returns 403 with a fixed
  message. Cross-tenant attempts are logged server-side only.

### Trust boundaries

- **Sandbox env is denylisted.** `POST /sandboxes` strips server secrets
  (`_SANDBOX_ENV_DENYLIST`) from the child environment before invoking the
  L3 backend, and requires an explicit `scans_workspace_root` to bound the
  blast radius.
- **Webhook dispatch errors are sanitized.** `requests.RequestException`
  details (URLs, headers) are logged, not returned in the dispatch result
  `error` field.
- **Health probes report status, not internals.** DB/disk/SMTP probe
  failures surface as fixed messages ("Database unreachable", "SMTP
  unreachable"), with the underlying exception logged.

## Consequences

- Callers of `run_project` must treat `"error" in result` as the failure
  signal and must not assume `success` is always present.
- Adding a new endpoint that returns `JSONResponse` on an error path requires
  `response_model=None`; the convention is enforced by review, not by a
  linter.
- The sanitized-error contract means operators diagnose failures from logs
  (`logger.exception`), not from API responses — by design, to avoid leaking
  internals at the trust boundary.
