# WO5.0.0-006 — Serve: scheduler cleanup bypasses the severity-aware audit retention

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/audit-retention`)
**Priority:** P0 · Effort S · Risk L
**Scope:** `picosentry/serve/services/scheduler.py`, `picosentry/serve/services/audit_cleanup.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + new test: critical/high rows older than the flat retention window survive the 6-hourly `periodic_cleanup` job.

## Objective
WO4.0.0-004's "critical survives" guarantee must hold in the only automatic purge path.

## Evidence (verified 2026-08-18, explorer SA-T; live repro)
`scheduler.py:384` passes `retention_days=settings.database.audit_retention_days` (default 90) into `purge_audit_logs`, whose flat path (`audit_cleanup.py:80-98`) ignores severity. Live: critical/high rows 100d old → deleted by the scheduler-style call. The per-severity policy (critical 365d / high 180d, `audit_cleanup.py:15-21`) only runs via admin `POST /audit/purge` without `retention_days` — i.e. never automatically. The `periodic_cleanup` job is registered at every boot (`server.py:213-220`) and enforces flat 90d. Interaction pair: severity purge (WO-004) × scheduler wiring.

## Deliverables
1. Scheduler calls the policy path (`purge_audit_logs()` with no flat override); flat `retention_days` stays admin-only.
2. Test pinning "critical survives the automatic job".
