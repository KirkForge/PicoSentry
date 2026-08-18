# WO5.0.0-019 — Sandbox: landlock verdict parity + degraded honesty

**Series:** WO5.0.0 (exploration round 2026-08-18; folds WO4.0.0-001 remainder 2026-08-18)
**Status:** DONE (2026-08-18, backend merge `aa73aee7` worker SA-AC; CI job in `d0fc6437` agent SA-AG) — shared compute_verdict(events, exit_code) across subprocess/seccomp/seatbelt/landlock; landlock 125/126/127 → degraded (was clean policy DENY) + seccomp-stub 126/127 fixed the same way (new verified bug fixed en route); ABI<2/3 FS ceilings surfaced degraded+logged; parity tests mocked + real (96 landlock tests green on kernel 7.0, 38 seccomp-trace, 24 malicious/containment). Deliverable 4: `landlock-real-exec` push-tier CI job (ubuntu-24.04) GREEN in run 32137930302. Deliverable 5 (seccomp composition) remains a documented ceiling per ADR-002.
**Owner:** (unassigned — worktree `wo/5.0.0/landlock-parity`)
**Priority:** P1 · Effort M · Risk M
**Scope:** `picosentry/sandbox/l3/backends/{landlock_backend.py,seccomp_backend.py,subprocess_backend.py,seatbelt_backend.py}`, `tests/sandbox/` (real-exec where kernels support: `PICODOME_HAS_LANDLOCK=1`)

**Gate:** `bash scripts/test.sh fast` + test asserting identical verdicts across backends for the same command+policy (allow exit 1/2 commands); landlock infra-failure exits marked degraded; unhandled FS-ceiling bits flagged.

## Objective
The same command + policy must yield the same `l3_verdict` regardless of host backend, and landlock's FS-ceiling gaps must be visible as `degraded`, not silently absent.

## Evidence (verified 2026-08-18, explorer SA-S; airtight chain — no landlock kernel on this host)
1. **Verdict semantics diverge**: `landlock_backend.py:582` returns ALLOW iff exit==0, while subprocess/seccomp/seatbelt are event-driven (`subprocess_backend.py:298-308`, `seccomp_backend.py:468-476`, `seatbelt_backend.py:327`). `grep` with no match (exit 2) or `npm audit` findings (exit 1) → DENY on landlock, ALLOW on seccomp for the identical command+policy; downstream DENY statistics differ per host backend.
2. **Infra failures reported as policy DENY**: landlock exit codes 125/126/127 → `DENY` with `degraded=False`.
3. **Unhandled FS-ceiling bits neither degraded nor logged**: ABI<2/3 gaps (REFER/TRUNCATE) silently unenforced.

## Deliverables
1. Event-driven verdict helper shared with seccomp; exit-code → degraded mapping for infra failures.
2. Degraded flag/log for FS ceilings the kernel ABI can't express.
3. Cross-backend verdict parity test (mocked + real-exec env-gated).
4. (Folded from WO4.0.0-001 deliverable 6) Real-execution landlock CI job: ubuntu-24.04 runner, `PICODOME_HAS_LANDLOCK=1` round-trip (restrict → EACCES) so the backend is proven on real kernels in CI, not just env-gated locally.
5. (Folded from WO4.0.0-001 deliverable 5, optional) seccomp+landlock composition (defense in depth) — documented ceiling today per ADR-002:108-109.
