# WO6.0.0-005 — Sandbox: seccomp-trace verdict parity break (benign nonzero exits = KILL, infra failures clean)

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/seccomp-trace-parity`)
**Priority:** P0 · Effort M · Risk M
**Scope:** `picosentry/sandbox/l3/backends/seccomp_trace/{orchestrator.py,event_parser.py}`, `tests/sandbox/test_verdict_parity.py`

**Gate:** `bash scripts/test.sh fast` + seccomp-trace added to the parity matrix: `sh -c "exit 3"` → ALLOW (like every backend); missing command → DENY+degraded; signal death → KILL. Env-gated real run pasted (`PICODOME_HAS_SECCOMP=1`).

## Objective
WO5-019 unified verdicts across subprocess/seccomp/seatbelt/landlock — seccomp-trace was left out of the matrix and diverges on all three axes.

## Evidence (verified 2026-08-18, explorer SA-AQ; live repro repro_verdict_parity.py)
- `orchestrator.py:260-268`: LIFECYCLE event → `ALLOW if exit_code == 0 else KILL`; `:305` `degraded=False` always; `event_parser.py:95-103` private `compute_verdict` only special-cases `-1`.
- Live: `sh -c "exit 3"` → subprocess `ALLOW exit=3`, seccomp-trace **KILL degraded=False**. Missing command → subprocess `DENY (L3-EXEC-001)`, seccomp-trace **KILL exit=127 degraded=False** (infra failure as clean policy verdict).
- Contradicts the shared helper's own contract (`l3/backends/base.py:13-29`: "a command that merely exits nonzero … is NOT a policy violation").
- `test_verdict_parity.py:87-95` delegates subprocess/seccomp/seatbelt only.

## Deliverables
1. Delete the private `compute_verdict` + the LIFECYCLE-KILL rule; use the shared helper; port the 125/126/127 → DENY+degraded branch.
2. seccomp-trace seat in the parity test.
