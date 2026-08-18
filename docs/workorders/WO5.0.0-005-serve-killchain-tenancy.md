# WO5.0.0-005 — Serve: kill-chain escalation reads org from the payload, which never carries it

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** DONE (2026-08-18, merge `4a5cad75`, worker SA-X) — one-line root fix (`org_id=evt.org_id`); other two payload-org readers audited and left as-is (both read JWT claims which genuinely carry org_id); regression test tests/serve/test_killchain_tenancy.py (two orgs, negative assertions on org-NULL alerts + org-B artifacts; mutation-verified). Post-merge order-dependence fixed centrally in `1b312f10` (event_bus.shutdown() from earlier lifespan tests cleared subscribers — test now re-registers the production subscriber deterministically).
**Owner:** (unassigned — worktree `wo/5.0.0/killchain-tenancy`)
**Priority:** P0 · Effort S · Risk L
**Scope:** `picosentry/serve/services/orchestrator.py`, sweep of all `payload.get("org_id")` readers, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + new test: two orgs, each with a chain; org A's run completes → only org A's chains escalate/alert/broadcast.

## Objective
The completed-run subscriber must take org from `Event.org_id`, not the payload — and every other payload-org reader must be audited.

## Evidence (verified 2026-08-18, explorer SA-T; live repro + orchestrator-confirmed by orchestrator)
`orchestrator.py:68-77`: subscriber lambda `evt.payload.get("org_id")`. `orchestrator.py:337-350`: publish puts `org_id` on `Event.org_id` (kwarg), NOT in the payload dict. Live: published the exact completed payload with `org_id="7"` → subscriber captured `org=None`. Chain: `CorrelationEngine.on_run_completed` (`correlation/engine.py:223-241`) always calls `critical_chains(org_id=None)` → every tenant's run escalates every other tenant's chains → `_chain_escalated_alert` (`server.py:121-143`) stores alert with `org_id=None` → WS system broadcast of other orgs' artifact/narrative data; `_trigger_cross_layer_analysis` fires cross-org. Same bug class as WO4.0.0-005, different mechanism (org stamping landed; reader reads the wrong field). Grep found two more `payload.get("org_id")` readers to audit: `middleware/audit.py:146`, `services/auth.py:339`.

## Deliverables
1. One-line fix: `org_id=evt.org_id`.
2. Audit + fix the other two payload-org readers (verify whether their publishers put org in payload).
3. Two-org escalation regression test.
