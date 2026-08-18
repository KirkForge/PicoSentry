# WO5.0.0-015 — Scan: selection & worker honesty (dropped rules, rules=[], intelligence mode)

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** DONE (2026-08-18, merge `8a0fbe2f`, worker SA-Y) — explicit-but-deselected rules → `RuleExecution(status="skipped", error=…)` + `scan_completeness: partial`; CLI exits 2 when explicit selection left nothing running; `rules` is-not-None semantics (`[]` → zero rules); `--timeout` worker forwards `intelligence_mode` (Process kwargs, old callers compatible); `--validate` help synced to the real 0.94/0.84 floors. 13 tests.
**Owner:** (unassigned — worktree `wo/5.0.0/scan-selection`)
**Priority:** P1 · Effort S-M · Risk L
**Scope:** `picosentry/scan/engine.py`, `picosentry/scan/cli_service.py`, `picosentry/scan/_cli_service_worker.py`, `picosentry/scan/cli_commands/scan.py`, `tests/scan/`

**Gate:** `bash scripts/test.sh fast` + new tests: explicitly-requested rule deselected by ecosystem shows up as skipped/failed in the result (not a silent clean); `rules=[]` runs no rules; timeout-worker engine receives `intelligence_mode`.

## Objective
An explicit rule selection must never silently yield a clean verdict, and worker processes must honor the caller's config.

## Evidence (verified 2026-08-18, explorer SA-R; live repros)
1. **Explicit rules silently dropped** (MEDIUM): selection happens before ecosystem filters (`engine.py:344,355-401`); requested rule filtered out → early return with 0 findings, 0 rule_executions (no `scan_completeness` in output), one log warning. Live: go project + `rules=["L2-POST-001"]` → findings 0, executions `[]`. Related: `rules=[]` (falsy) means "all rules" — a daemon client sending `"rules": []` gets a full scan (`engine.py:344` uses `if rules`, not `is not None`). Prior art: firewall worker hit the same drop empirically (lessons 2026-08-17).
2. **`--timeout` worker drops `--intelligence connected`** (MEDIUM): `_run_scan` builds the parent engine with the configured mode but spawns `_scan_worker(target, rules, corpus_dir, advisory_db, queue)` — worker signature has no intelligence param and builds `create_default_engine(...)` offline (`_cli_service_worker.py:18-33`, args tuple at `cli_service.py:289`). `scan . --intelligence connected --timeout 300` silently runs offline.
3. **`--validate` help floors stale** (LOW): `cli_commands/scan.py:185` says "precision >= 0.84 and mean recall >= 0.70"; code gates at `>= 0.94` / `>= 0.84` (`cli_service.py:720-721`).

## Deliverables
1. Explicitly-deselected rules recorded as `RuleExecution(status="skipped", error="ecosystem X not detected")` and/or exit 2; `rules == []` → no rules.
2. Forward `config.intelligence` through the worker args tuple (+ test).
3. Sync the help text to the real floors.
