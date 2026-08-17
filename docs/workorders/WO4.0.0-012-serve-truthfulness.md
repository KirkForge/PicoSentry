# WO4.0.0-012 — Serve: truthfulness (scheduler, health, anomaly, status)

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** DONE 2026-08-17 (worktree `wo/4.0.0/serve-p1`, branch commit "serve: WO-012/013 truthfulness+concurrency") — evidence: `tests/serve/test_scheduler_worker.py` (TestHealthCheckJob, TestRejectedJobsReschedule, TestReportJobDelivery, TestUpdateAndTrigger), `tests/serve/services/test_anomaly_detector.py::TestRuleSemantics`, `tests/serve/test_api.py::TestSchedulerEndpoints` (update/trigger), `tests/serve/test_health_router.py` (threat_score)
**Owner:** worker subagent (worktree `wo/4.0.0/serve-p1`)
**Priority:** P1 · Effort S-M · Risk L
**Scope:** `picosentry/serve/services/{scheduler.py,anomaly_detector.py,_orchestrator_health.py}`, `picosentry/serve/api/routers/{health.py,scheduler.py}`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + new tests: health_check job succeeds and populates health_checks; rejected job reschedules; report output stored/delivered; anomaly rules 1/2/4 fire or are removed. — ALL GREEN (4991 passed repo-wide fast profile)

## Resolution notes
1. `health_check` branch added to `_execute_job` (calls `orchestrator.get_health_checks`, persists probes); runs off-thread with skip-while-running (slow set now `{batch, health_check}`).
2. Rejected paths restructured to fall through to the shared status-update + reschedule tail; added `JobScheduler.update_job`/`trigger_job` + `PATCH /scheduler/jobs/{id}` and `POST /scheduler/jobs/{id}/run`.
3. `report` job delivers via `orchestrator.alerts.send("system", "scheduled_report", ...)` — the alerts-table row is the stored, queryable copy.
4. Anomaly semantics implemented (choice: implement, not remove): counters evaluate as exact windowed delta over `duration_seconds` (last-in-window − last-before-window); gauges/histograms gate on sustained breach (`_breach_since`); `alert_channel` honored in `_fire_alert`; `metrics.api_request` now recorded by the audit middleware with a `status_class` label (rule label fixed `status=5xx` → `status_class=5xx`, shipped json threshold drift 0.5→10 corrected); `disk_used_pct` gauge recorded by the health probe (rule 3 live). Rules 1/2/4 verified firing end-to-end (`test_shipped_high_error_rate_rule_fires_from_live_5xx_traffic`).
5. `/status` `threat_score` = `orchestrator.get_status` intelligence aggregate (the health-latency average deleted); `metrics.threat_level` recorded in `get_status`.
