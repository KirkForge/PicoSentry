# WO4.0.0-001 — Landlock backend: make it actually work

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/4.0.0/landlock-truth` off `origin/dev`)
**Priority:** P0 · Effort L · Risk M
**Scope:** `picosentry/sandbox/l3/backends/landlock_backend.py`, `tests/sandbox/test_landlock_backend.py`, `docs/adr/ADR-002` addendum

**Gate:** `bash scripts/test.sh fast` + env-gated real round-trip test (`PICODOME_HAS_LANDLOCK=1`: restrict → EACCES assert) on a ≥6.2 kernel runner; `uv run picosentry sandbox pipeline true --backend landlock` succeeds on aarch64/6.x host.

## Objective
The landlock backend is dead on x86_64 and policy-blind everywhere. Make it real.

## Evidence (verified 2026-08-17)
- `_SYSCALL_NUMBERS` maps x86_64→(446,447,448); the kernel's real numbers are 444/445/446 (`asm/unistd_64.h`). Live probe: `is_available: False` → every "landlock" run silently falls back to seccomp. `tests/sandbox/test_landlock_backend.py:154` **asserts the wrong numbers** — the test enshrines the bug.
- Policy argument ignored entirely: fixed RO/RW path sets (220-222); `network_out: deny` not enforced at all (`handled_access_net=0`; NET_* constants are dead code).
- ALL-bits ruleset requires ≥6.2 (REFER/TRUNCATE) while the availability gate claims 5.13 — 5.13–6.1 hosts fail the probe with generic EINVAL and silently fall back.
- `/tmp` becomes RW when cwd=None; read-set includes all of `/proc` + EXECUTE on `/dev`.

## Deliverables
1. Corrected syscall table (x86_64 444/445/446 + verify aarch64) + test asserting against a generated table, not literals.
2. Kernel-version-scoped access bits (probe REFER/TRUNCATE/NET support; honest ≥6.2 message).
3. Translate `Policy` paths → rulesets; enforce `network_out: deny` via NET_PORT/CONNECT where kernel ≥6.7 (documented ceiling otherwise).
4. Workspace-root resolution (no bare `/tmp` RW); drop `/proc` full-read and `/dev` EXECUTE from defaults.
5. Optional seccomp+landlock composition (defense in depth).
6. Real-execution CI job (ubuntu-24.04, opt-in env like `PICODOME_SANDBOX_TESTS`).
