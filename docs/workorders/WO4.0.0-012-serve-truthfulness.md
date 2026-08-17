# WO4.0.0-012 — Serve: truthfulness (scheduler, health, anomaly, status)

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/4.0.0/serve-truth`)
**Priority:** P1 · Effort S-M · Risk L
**Scope:** `picosentry/serve/services/{scheduler.py,anomaly_detector.py,_orchestrator_health.py}`, `picosentry/serve/api/routers/{health.py,scheduler.py}`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + new tests: health_check job succeeds and populates health_checks; rejected job reschedules; report output stored/delivered; anomaly rules 1/2/4 fire or are removed.

## Objective
The job table, health endpoints, and anomaly rules must tell the truth.

## Evidence (verified 2026-08-17)
1. `health_check` scheduled job always "fails" — `_execute_job` has no branch for it (scheduler.py:281-357) → status="failed" written every N minutes; `health_checks` table only populated by manual /health → anomaly `health_status` rule + `/health/history` run on stale data.
2. Rejected jobs (bad category/params) `return` before the reschedule block (scheduler.py:279,300 vs :390-392) — one bad param permanently kills the job; no update_job/run-now endpoint to recover.
3. Scheduled `report` command binds `_report` and never stores/sends it (scheduler.py:330-334) — the cron produces nothing.
4. Anomaly detector: `duration_seconds` never evaluated; `alert_channel` ignored; `high_error_rate` wants label `status="5xx"` but metrics record `"500"`; `api_request()` has ZERO callers so its metrics never exist — default rules 1/2/(4) can never fire.
5. `/status` `threat_score` = average health latency (health.py:134-136) — nonsense on a flagship endpoint.

## Deliverables
1. health_check branch calling perform_health_checks (off-loop); rejected-path reschedule + skip-status persistence; `update_job` + trigger-now endpoints; report delivery (store + webhook/alert channel).
2. Anomaly rules: implement documented semantics or remove dead rules + fix label mismatch; record `api_request` from middleware.
3. `/status` threat_score → real composite (chain escalations + anomaly firings) or rename honestly.
