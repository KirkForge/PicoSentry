# WO6.0.0-020 — Serve: multi-worker riders (SIGTERM parity, topology detection, sync deps on loop, add_job TOCTOU, standby lag, UTC pinning)

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/serve-riders`)
**Priority:** P1 · Effort M · Risk L
**Scope:** `picosentry/serve/api/server.py`, `picosentry/serve/api/deps.py`, `picosentry/serve/api/routers/ws.py`, `picosentry/serve/services/scheduler.py`, `picosentry/serve/config/settings.py`, `picosentry/serve/database/pools.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + tests: SIGTERM stops the outbox poller; add_job cross-org race returns 409 not the winner's id; PG connections pin UTC; deps off the loop.

## Objective
The WO5-031/032 remainder riders found by the seam hunt.

## Evidence (2026-08-18, explorers SA-AR/SA-AU)
1. **SIGTERM skips poller shutdown + ws main_loop reset** (`server.py:430-439` vs `:268-275`): post-`db.close()` the poller re-opens connections and keeps polling during the shutdown window.
2. **Topology detection**: `uvicorn --workers N` WITHOUT `PICOSHOGUN_API_WORKERS` silently disables every multiworker mechanism (posture derived from the env var only, `settings.py:260-265`) — warn when `WEB_CONCURRENCY`/uvicorn markers are present with outbox=auto.
3. **Sync DB reads on the loop** (convention violation): `deps.py:153-161` `require_org_membership` and `ws.py:17-23` are `async def` calling DB directly (get_current_user is deliberately sync for threadpooling).
4. **add_job cross-org TOCTOU** (`scheduler.py:153-167` vs `:207-211`): two orgs racing one name → loser's IntegrityError fallback returns the WINNER's id with 201, bypassing the cross-org guard. Re-check org inside the fallback.
5. **Standby removal lag**: remove/disable on a standby propagates to the leader only at `reload_every` (30s default) — a removed every-minute job can fire once more. Jobs-version bump or documented ceiling.
6. **PG timezone**: lease `expires_at TIMESTAMP` compared against tz-aware params — correct only if all sessions share one TZ; nothing pins it (`SET TIMEZONE 'UTC'` at acquire). Same family: quota-day boundary `CURRENT_DATE` shifts by session TZ. Sqlite multi-host skew ceiling: document.

## Deliverables
Per item; tests per the gate.
