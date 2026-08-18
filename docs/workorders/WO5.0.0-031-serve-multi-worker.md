# WO5.0.0-031 — Serve: multi-worker / horizontal readiness (folds WO4.0.0-020 remainder)

**Series:** WO5.0.0 (fold 2026-08-18 from WO4.0.0-020 PARTIAL)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/serve-multiworker`)
**Priority:** P2 · Effort L · Risk H
**Scope:** `picosentry/serve/**` (event_bus, scheduler, rate_limit, metrics, websocket_manager), `deploy/helm/` (new serve chart)

**Gate:** a 2-worker uvicorn integration test green (WS fanout across workers, scheduler single-fire via leader lock, shared rate limits, aggregated metrics); support matrix documented.

## Objective
`API_WORKERS>1` becomes a supported, tested configuration.

## Evidence (carried, verified 2026-08-17; atomic rate-limit persistence + boot-migration race already DONE in WO4)
Per-process state breaks multi-worker today: event_bus history + WS fanout in-process (workers blind to each other's events); scheduler assumes single instance (duplicate fires — note WO5.0.0-021 fixes the same-job duplicate-entry bug WITHIN one process; this WO is the cross-worker leader lock); rate-limit memory backend = limits × workers; metrics per-process (WO5.0.0-007's render fix is per-process too); WS slow-consumer head-of-line blocking (serial awaited sends, websocket_manager.py:100-102); no serve helm chart (deploy/helm = picodome only).

## Deliverables
1. Event fanout via redis pub/sub or DB outbox; WS send fan-out non-blocking per consumer.
2. Scheduler leader lock at dispatch; rate-limit redis default when workers>1.
3. Metrics aggregation story across workers; serve helm chart + HPA docs; support matrix.
