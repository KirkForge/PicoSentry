# WO7.0.0-022 — Watch: gateway upstream 200 with error body attests `output_valid: true`

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/gateway-error-body-attested`)
**Priority:** P1 · Effort S · Risk L
**Scope:** `picosentry/watch/gateway.py`, `tests/watch/`

**Gate:** `bash scripts/test.sh fast` + test: a 200 upstream response with `{"error": {...}}` (no `choices`) is NOT attested `output_valid: true`; the error message is scanned.

## Objective
Upstream returns 200 with `{"error": {...}}` (no `choices`) → `output_parts` is empty → `output_guard` validates an empty string → `output_valid: true`. The error message is never scanned.

## Evidence (verified 2026-08-20, explorer SA-watch; file:line chain)
- `gateway.py:347-405`: the choices-extraction path yields no parts for an error body; the empty parts list flows to `output_guard` which returns `valid` on empty input.
- The error message field is never fed to the guard.

## Deliverables
1. Detect missing `choices` (or presence of an `error` field); do NOT attest `output_valid: true`; route the error message through the guard.
2. Regression test per the gate.