# WO7.0.0-021 — Watch: gateway non-JSON 200 passes output unscanned with no `picowatch` metadata

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/gateway-nonjson-unscanned`)
**Priority:** P1 · Effort S · Risk L
**Scope:** `picosentry/watch/gateway.py`, `tests/watch/`

**Gate:** `bash scripts/test.sh fast` + test: a 200 non-JSON upstream response with `block_on_output_violation=False` is returned with a `picowatch` metadata block carrying `output_scanned: false`.

## Objective
When `json.loads` fails and `block_on_output_violation=False`, the gateway returns the raw response with no `picowatch` field or header. Downstream cannot distinguish "scanned clean" from "unscanned".

## Evidence (verified 2026-08-20, explorer SA-watch; file:line chain)
- `gateway.py:323-341`: non-JSON 200 path returns the body as-is; no `picowatch` metadata added.
- Scanned responses carry a `picowatch` block; this path does not → ambiguity.

## Deliverables
1. Add a `picowatch` metadata block with `output_scanned: false` (and a header if appropriate) to the non-JSON pass-through path.
2. Regression test per the gate.