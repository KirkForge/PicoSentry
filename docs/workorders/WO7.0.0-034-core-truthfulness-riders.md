# WO7.0.0-034 — Core: truthfulness riders round 4 (doctor, CLI cluster, CLI serve, README, COMPONENT_STATUS, k8s, picodome ro-fs)

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/core-truthfulness-4`)
**Priority:** P2 · Effort M · Risk L
**Scope:** `picosentry/_core/doctor.py`, `picosentry/sandbox/cli_commands/cluster.py`, `picosentry/cli_commands/serve.py`, `README.md`, `picosentry/experimental.py`, `deploy/kubernetes/deployment.yaml`, `deploy/helm/picodome/templates/deployment.yaml`, `tests/core/`

**Gate:** `bash scripts/test.sh fast` + per-item assertions (see deliverables).

## Objective
A cluster of small truthfulness gaps surfaced by the SA-core explorer — each individually small, collectively eroding the "what we claim is what we ship" contract.

## Evidence (verified 2026-08-20, explorer SA-core; file:line chain)
- `picosentry/_core/doctor.py`: version-check gap (doesn't compare against the right source).
- `picosentry/sandbox/cli_commands/cluster.py:189`: wrong prog name in error/help text.
- `picosentry/cli_commands/serve.py:72-78`: falsy-zero flags treated as unset.
- `README.md:154-155`: chapter index skips ch.22.
- `picosentry/experimental.py`: firewall absent from `COMPONENT_STATUS`.
- `deploy/kubernetes/deployment.yaml`: missing `PICODOME_JOB_STORE_DIR` env.
- `deploy/helm/picodome/templates/deployment.yaml`: sqlite-on-readonly-fs (no PVC for the sqlite store path).

## Deliverables
1. Doctor version check: compare against the correct source (and test the comparison).
2. CLI cluster: correct prog name.
3. CLI serve: distinguish falsy-zero from unset for the affected flags.
4. README: add ch.22 to the chapter index.
5. `experimental.py` COMPONENT_STATUS: add firewall with an honest status.
6. k8s deployment: add `PICODOME_JOB_STORE_DIR` env.
7. picodome helm: mount a PVC for the sqlite store path (don't run sqlite on a readonly FS).
8. Regression test per item.