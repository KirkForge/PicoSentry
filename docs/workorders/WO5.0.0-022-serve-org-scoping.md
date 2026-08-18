# WO5.0.0-022 — Serve: org-scoping remainder (threat score, anomaly filters, rule mutation surface)

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/serve-orgscope`)
**Priority:** P1 · Effort M · Risk M
**Scope:** `picosentry/serve/services/{orchestrator.py,intelligence.py,anomaly_detector.py}`, `picosentry/serve/api/routers/anomaly.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + new tests: org A's `/status` threat score unaffected by org B's intelligence; anomaly alerts for org A never starved by org B's volume; anomaly rule PATCH by org B's operator does not affect org A's rules.

## Objective
Org-scoped surfaces must aggregate org-scoped data; anomaly machinery must be per-org or explicitly global.

## Evidence (verified 2026-08-18, explorer SA-T; code chains + live repros)
1. **`/status` and `/dashboard/summary` report a GLOBAL threat score**: `orchestrator.py:170` `threat_score = self.intel.get_aggregate_score()`; `intelligence.py:331-370` keys by project only, `ingest(org_id=…)` ignores org, `_load_historical()` loads all orgs. Org A's threat_score (and `metrics.threat_level` gauge, `orchestrator.py:173`) reflects every tenant. Contrast the properly org-scoped `/intelligence/threat-score` (`routers/projects.py:146-160`) — two endpoints, two semantics, one leaky. Intelligence table has org_id since migration 10.
2. **Anomaly alert org filter applied after LIMIT**: `anomaly_detector.py:444-471` — fetches `LIMIT ?` globally then filters by org in Python; busy multi-tenant deployments starve later orgs. org_id column exists (migration 13).
3. **Anomaly rule updates are global mutations**: any org's WRITE_ANOMALY operator PATCHes rules for every tenant (`routers/anomaly.py:72-91`); rules carry no org; `_save_rules` writes `config/anomaly_rules.json` inside the install tree (`anomaly_detector.py:494-499`) — read-only wheel/container deployments get unhandled OSError → 500.
4. **Org-filtered /metrics JSON hides api request/latency series**: `metrics.py:154-158` filters by an `org_id` label `api_request` never sets (`middleware/audit.py:198`) → org users see empty `api_requests_total`/latency data (empty-meaningful class). Coordinate with WO5.0.0-007 deliverable 3.

## Deliverables
1. Org-filter `get_aggregate_score`; reconcile the two threat-score endpoints in docs.
2. SQL-side org filter for anomaly alerts.
3. Anomaly rules: per-org scoping or admin-only global (owner decision — folds into the pending system-event/org ADR); config write made robust for read-only installs.
4. Org label decision for api metrics (shared with WO5.0.0-007).
