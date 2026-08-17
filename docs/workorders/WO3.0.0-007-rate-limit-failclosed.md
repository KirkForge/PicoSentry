# WO3.0.0-007 — Distributed Rate Limiting Fail-Closed

**Series:** WO3.0.0 (improvement loop)
**Status:** COMPLETE (verified in code 2026-08 — see workorders/README.md)
**Owner:** subagent (worktree `wo/3.0.0/rate-limit-failclosed`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/serve/ -m "not slow"`

## Objective
Make distributed rate limiting fail-closed when Redis is unavailable, so a Redis outage does not silently degrade to per-replica (weaker) limits.

## Root cause being addressed
Rate limiting 7/10: `RedisRateLimitBackend` (`picosentry/serve/middleware/rate_limit_redis.py`) is best-effort — on Redis failure it returns fallback local values, losing global enforcement (review: "Redis fallback is silent (per-replica limits only)").

## Scope
- `picosentry/serve/middleware/rate_limit_redis.py` — replace the silent fallback with a fail-closed policy (reject or strictly-limit when Redis is down), OR document the tradeoff and make it configurable (`fail-open` / `fail-closed`)
- Keep the in-memory DDoS shield as defense-in-depth
- Config knob for the outage policy

## Done-condition
- When Redis is down, the policy is explicit (fail-closed rejects or strictly limits; configurable)
- No silent degradation to weak per-replica limits
- All gates green

## Notes
- Do NOT rewrite tests to pass.
- Preserve honest-doc annotations.
