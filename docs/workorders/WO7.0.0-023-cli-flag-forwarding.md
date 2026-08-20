# WO7.0.0-023 — CLI: flag forwarding gaps (admission `--scan-fail-closed`, daemon cluster + redis, watch `--verbose`)

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/cli-flag-forwarding`)
**Priority:** P1 · Effort M · Risk L
**Scope:** `picosentry/cli_commands/{admission.py,daemon.py,watch.py}`, `picosentry/sandbox/cli_commands/{admission.py,daemon.py}`, `picosentry/watch/cli.py`, `tests/cli/`

**Gate:** `bash scripts/test.sh fast` + parity tests: every flag on the inner module's parser is forwarded by the unified wrapper (asserted by table-driven test over all three commands).

## Objective
The unified CLI wrappers drop flags the inner modules accept. Users hitting the unified entrypoint silently lose `--scan-fail-closed`, cluster/redis daemon flags, and `--verbose`.

## Evidence (verified 2026-08-20, explorer SA-core; file:line chain)
- `cli_commands/admission.py`, `cli_commands/daemon.py`, `cli_commands/watch.py`: wrappers forward a subset of flags.
- Inner modules `sandbox/cli_commands/{admission.py,daemon.py}` and `watch/cli.py` accept the dropped flags.

## Deliverables
1. Forward every flag from each inner module's parser through the unified wrapper.
2. Parity tests per the gate (table-driven, one row per flag).