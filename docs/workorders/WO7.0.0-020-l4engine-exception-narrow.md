# WO7.0.0-020 — Sandbox: `L4Engine.analyze` exception tuple too narrow — `KeyError` kills the scan

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/l4engine-exception`)
**Priority:** P1 · Effort S · Risk M
**Scope:** `picosentry/sandbox/l4/engine.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + test: an L4 rule that raises `KeyError` mid-analysis is caught and recorded as a rule error, not a scan crash; the scan completes with other rules' results.

## Objective
`L4Engine.analyze` catches `(OSError, RuntimeError, ValueError, TypeError, AttributeError)` but not `KeyError`, `IndexError`, `LookupError`, etc. A rule raising one of those kills the whole scan.

## Evidence (verified 2026-08-20, explorer SA-sandbox; file:line chain)
- `engine.py:69-77`: `except (OSError, RuntimeError, ValueError, TypeError, AttributeError) as e:` — narrow tuple.
- A rule that does `RULE_INFO[name]` with an unknown key raises `KeyError` — uncaught, scan aborts.

## Deliverables
1. Widen to `except Exception as e:` (record the rule as errored, continue with others); preserve the exception type in the verdict for visibility.
2. Regression test per the gate.