# WO4.0.0-020 — Serve: multi-worker / horizontal readiness

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** CLOSED-FOLDED (2026-08-18) — remainder (event fanout, scheduler leader lock, redis-default rate limiting, metrics aggregation, serve helm chart + support matrix) moved to **WO5.0.0-031**. Landed & shipped in v2.1.2: atomic rate-limit persistence (`transaction(immediate=True)` around DELETE+INSERTs); boot migration race closed (per-migration transaction + `ON CONFLICT (version) DO NOTHING`, two-worker boot smoke test) — evidence `tests/serve/test_db_rwlock.py::TestRateLimitFlushAtomicity`, `TestMigrationBootRace`. `API_WORKERS>1` remains unsupported until WO5.0.0-031
**Owner:** worker subagent (worktree `wo/4.0.0/serve-p1`)
**Priority:** P2 · Effort L · Risk H
**Scope:** `picosentry/serve/**` (event_bus, scheduler, rate_limit, metrics, anomaly, database boot), `deploy/helm/` (new serve chart)

**Gate:** a 2-worker uvicorn integration test green (WS fanout, scheduler single-fire, rate limits shared, metrics aggregate); documented support matrix. — NOT MET (partial: unit-level race + atomicity tests only)

## Objective
`API_WORKERS>1` becomes a supported, tested configuration.

## Evidence (verified 2026-08-17)
Per-process state breaks multi-worker today: event_bus history + WS fanout are in-process (workers can't see each other's events); scheduler assumes single instance (duplicate fires); rate-limit memory backend = limits × workers (and its DB persistence is non-atomic, DELETE+re-INSERT outside a transaction — rate_limit.py:138-152); metrics per-process; boot migration race on fresh DB with workers>1 (manager.py:246-280); WS slow-consumer head-of-line blocking (serial awaited sends, websocket_manager.py:100-102); no serve helm chart (deploy/helm = picodome only).

## Deliverables
1. Event fanout via redis pub/sub or DB outbox; scheduler leader lock at dispatch; rate-limit redis default + atomic persist. — atomic persist DONE (single `transaction(immediate=True)` around DELETE+INSERTs); the rest NOT DONE.
2. Metrics aggregation story; boot migration lock. — boot migration race DONE; metrics aggregation NOT DONE.
3. Serve helm chart + HPA docs; support matrix documented. — NOT DONE.
