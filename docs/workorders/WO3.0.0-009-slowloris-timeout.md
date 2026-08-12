# WO3.0.0-009 — Slowloris / Header-Read Timeout

**Series:** WO3.0.0 (improvement loop)
**Status:** OPEN
**Owner:** subagent (worktree `wo/3.0.0/slowloris-timeout`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/serve/ -m "not slow"`

## Objective
Close the slowloris gap: cap header-read / connection-trickle time so a client slowly sending headers cannot hold connections open indefinitely.

## Root cause being addressed
Rate limiting / DoS 7/10: `RequestTimeoutMiddleware` bounds slow *body/response* but there is no header-read deadline (classic slowloris). The DDoS shield is in-memory per-replica.

## Scope
- `picosentry/serve/api/server.py` — configure uvicorn `limit_concurrency`, header-read timeout, and/or `limit_max_requests`; or add a middleware that bounds time-to-first-header
- Document/enforce at the reverse-proxy layer if that's the better place (nginx/ingress `client_header_timeout`)
- Config knobs for the timeout values

## Done-condition
- A slow header-trickle connection is closed/timed out within the configured window
- All gates green

## Notes
- Do NOT rewrite tests to pass.
- Preserve honest-doc annotations.
