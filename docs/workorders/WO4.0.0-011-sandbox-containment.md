# WO4.0.0-011 — Sandbox: containment hardening (killpg, RLIMIT_CPU/NPROC)

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** DONE 2026-08-17 (worktree `wo/4.0.0/sandbox-p1`) with one documented deviation: RLIMIT_NPROC defaults OFF (opt-in via PICODOME_PROCESS_LIMIT>0). RLIMIT_NPROC is per-UID HOST-wide while /proc sees only the PID namespace — any default bound made every fork fail on shared-UID hosts (verified empirically on this box: forks fail at limit 590 while /proc reports 74 uid procs). RLIMIT_CPU defaults 3600 s. Evidence: tests/sandbox/test_containment.py (group-kill regression, gated fork-flood round passes under PICODOME_SANDBOX_TESTS=1).
**Owner:** (unassigned — worktree `wo/4.0.0/containment`)
**Priority:** P1 · Effort M · Risk M
**Scope:** `picosentry/sandbox/l3/backends/**`, `picosentry/sandbox/l3/_rlimits.py`, `picosentry/sandbox/process_manager.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + env-gated malicious-workload round: grandchild process killed on timeout; fork-bomb bounded by NPROC; CPU ceiling enforced.

## Objective
Bounded blast radius per run: kill the process group on timeout, cap CPU and process count, fix the subprocess-backend post-kill hang.

## Evidence (verified 2026-08-17)
1. All backends SIGKILL only the direct child (seccomp_backend.py:449, landlock_backend.py:331, process_manager.py:78, subprocess_backend.py:98) — orphaned grandchildren survive (still confined but unbounded wall-time, holding stdout write-ends).
2. Subprocess backend hangs forever: `proc.communicate()` (no timeout) after kill blocks on the grandchild-held pipe (subprocess_backend.py:99) — hits Windows, macOS-without-seatbelt, and every degraded run.
3. `_rlimits.py:30-32` sets AS/FSIZE/NOFILE only — no RLIMIT_CPU (orphan CPU burn), no RLIMIT_NPROC (fork-bomb under permissive seccomp policies exhausts the host process table).

## Deliverables
1. `setsid` + `killpg` timeout kill on all backends; close pipes after kill.
2. Fix the communicate() hang (killpg or pipe close before communicate).
3. RLIMIT_CPU + RLIMIT_NPROC with env knobs (`PICODOME_CPU_LIMIT_SECONDS`, `PICODOME_PROCESS_LIMIT`, 0=off).
