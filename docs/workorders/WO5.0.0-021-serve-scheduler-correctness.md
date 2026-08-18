# WO5.0.0-021 — Serve: scheduler correctness (double-fire, SMTP persistence, report scope, name squat)

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** DONE (2026-08-18, merge `134327f4`, worker SA-AD) — per-job queued-entry tracking, cancel-and-replace (boot/update/enable/restart leave exactly ONE entry; disable drops to zero); SMTP probe persisted + disabled/unknown no longer count as warnings in health_degraded; scheduled reports org-scoped end-to-end; same org+name+config → existing id, different config → 409.
**Owner:** (unassigned — worktree `wo/5.0.0/serve-scheduler`)
**Priority:** P1 · Effort M · Risk M
**Scope:** `picosentry/serve/services/{scheduler.py,_orchestrator_health.py}`, `picosentry/serve/api/server.py` (lifespan boot order), `picosentry/serve/services/anomaly_detector.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + new tests: restart + boot add_job leaves ONE queued entry per job; update/enable never multiplies; SMTP check rows appear in `health_checks`; scheduled report for org X contains only org X's data.

## Objective
Scheduler entries must be unique across boot/toggle cycles, health history must include every probe, and per-org jobs must use per-org data.

## Evidence (verified 2026-08-18, explorer SA-T; live repros)
1. **Duplicate queue entries → every restart double-fires all system jobs**: `_schedule_job` never cancels an existing entry (`scheduler.py:424-440`); `add_job`/`update_job`/`enable_job` re-enter while running (`:130-136,189-193`). Live: fresh process with a persisted job → `start()` 1 entry; lifespan `add_job` (boot order `server.py:203-230`: start precedes add_job) → 2 entries permanently; `update_job` → 2; `+enable_job` → 3. Consequences: double nightly backups/purges/health probes; org operators toggling via `PATCH .../enable` permanently raise firing rates.
2. **SMTP health check never persisted**: persist loop runs at `_orchestrator_health.py:126-133` but SMTP check appended after (lines 147-183). Live: checks include `smtp`, DB rows only database/disk_space/projects. `health_degraded` anomaly rule (`anomaly_detector.py:253-276`) permanently blind to the only component the probe times out on. (Inverse: `_get_health_value` counts "disabled" as warning — fix semantics together.)
3. **Scheduled per-org report delivers global data**: `scheduler.py:348-357` calls `generate_summary_report()` with no org, org-stamps only the alert delivery. Org X's scheduled report contains all tenants' numbers.
4. **Same-name job creation keeps stale config; cross-org name squat blocks creation** (`scheduler.py:114-128`): existing name + same org returns the old job id ignoring new cron/command/params (201 "scheduled", nothing changed); different org → 400.

## Deliverables
1. Track queued entries per job id; cancel-and-replace before `enter`.
2. Move SMTP append above the insert loop; decide disabled/unknown semantics for `health_degraded`.
3. Pass `org_id=job.org_id` into report generation.
4. Same-name+changed-config → update or 409; document name scoping (per-org).
