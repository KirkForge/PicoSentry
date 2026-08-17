# WO4.0.0-020 — Serve: multi-worker / horizontal readiness

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/4.0.0/multi-worker`)
**Priority:** P2 · Effort L · Risk H
**Scope:** `picosentry/serve/**` (event_bus, scheduler, rate_limit, metrics, anomaly, database boot), `deploy/helm/` (new serve chart)

**Gate:** a 2-worker uvicorn integration test green (WS fanout, scheduler single-fire, rate limits shared, metrics aggregate); documented support matrix.

## Objective
`API_WORKERS>1` becomes a supported, tested configuration.

## Evidence (verified 2026-08-17)
Per-process state breaks multi-worker today: event_bus history + WS fanout are in-process (workers can't see each other's events); scheduler assumes single instance (duplicate fires); rate-limit memory backend = limits × workers (and its DB persistence is non-atomic, DELETE+re-INSERT outside a transaction — rate_limit.py:138-152); metrics per-process; boot migration race on fresh DB with workers>1 (manager.py:246-280); WS slow-consumer head-of-line blocking (serial awaited sends, websocket_manager.py:100-102); no serve helm chart (deploy/helm = picodome only).

## Deliverables
1. Event fanout via redis pub/sub or DB outbox; scheduler leader lock at dispatch; rate-limit redis default + atomic persist.
2. Metrics aggregation story; boot migration lock.
3. Serve helm chart + HPA docs; support matrix documented.
