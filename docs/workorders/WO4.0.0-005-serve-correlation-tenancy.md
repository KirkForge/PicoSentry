# WO4.0.0-005 — Serve: correlation tenancy stamping

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** DONE (verified 2026-08-17, shipped in v2.1.2 — build_event_from_intel takes/stamps org_id (correlation/helpers.py:48-90), migration 19 correlation_events.org_id + index (database/_schema.py:872-887), org-stamped persistence + org in dedup key (correlation/persistence.py:43-131), org-scoped get_project/get_correlations in reports (_orchestrator_reports.py:58,91), org in alert cooldown key (alert_hub.py:68); tests/serve/test_correlation_tenancy.py)
**Owner:** (unassigned — worktree `wo/4.0.0/corr-tenancy`)
**Priority:** P0 · Effort M · Risk M
**Scope:** `picosentry/serve/services/_orchestrator_intel_helpers.py` (build_event_from_intel), `orchestrator.py`, `_orchestrator_reports.py`, `correlation/engine.py`, `alert_hub.py`, `picosentry/serve/database/_schema.py` (correlation tables org column), `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + new cross-tenant tests: org B's /chains and /reports/project/{id} never see org A's artifacts/intelligence; alert dedup keys include org.

## Objective
Close the remaining org=None leaks: correlation events, project reports, and alert dedup/escalation.

## Evidence (verified 2026-08-17)
1. `helpers.py:48-90` `build_event_from_intel()` takes no org_id; `orchestrator.py:341-351` ingests unstamped → engine treats org_id=None as visible-to-all (engine.py:168) → org B's `/chains` shows org A's artifact chains (rule ids, snippets, targets). The engine's org support exists; the primary producer doesn't stamp.
2. `_orchestrator_reports.py:58` calls `get_project` without the org_id it receives; `:91` `get_correlations` queries with no org filter → `/reports/project/{id}` leaks any org's intelligence mentioning the project + bypasses the ownership 404.
3. Alert cooldown key `f"{project_id}:{alert_type}"` has no org (alert_hub.py:66-79) → tenant A suppresses tenant B's alert; `on_run_completed` runs `critical_chains()` unscoped (engine.py:202-208) → any org's run re-escalates every org's chains.

## Deliverables
1. org_id through `build_event_from_intel` → `_execute_project`; persistence org columns + migration.
2. Org-scope `get_project`/`get_correlations` in reports.
3. Alert/dedup/escalation keys include org; escalation chains org-scoped.
4. This pays down the "system-event tenancy" design escalate for the correlation surface (WS/webhook paths already stamped).
