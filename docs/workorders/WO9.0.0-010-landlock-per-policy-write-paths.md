# WO9.0.0-010 — Sandbox: `L3-FILE-W-001` write paths are enforced by neither backend as written (landlock narrows to workspace, seccomp does not scope at all)

**Series:** WO9.0.0 (audit round 2026-08-23; re-scoped 2026-10-02 by the CI-gate session)
**Status:** OPEN (partial — honesty half landed in `11843c98`; enforcement half still open)
**Owner:** (unassigned)
**Priority:** P1 · Effort M · Risk M
**Scope:** `picosentry/sandbox/l3/backends/landlock_backend.py` (`_build_grants`), `picosentry/sandbox/l3/backends/seccomp_backend.py`, `picosentry/sandbox/l3/policy.py` (`L3-FILE-W-001`), `tests/sandbox/test_landlock_backend.py`, `docs/manual.md` (931/948/2580)

**Gate:** `bash scripts/test.sh fast` **from a clean `/tmp`** (see Trap 1) + a landlock real-exec test that a policy naming `/etc/pico-probe` grants write there and denies it elsewhere, run with `PICODOME_HAS_LANDLOCK=1` (this host has no landlock — CI job `landlock-real-exec` is the only place that tier executes).

## How far this session got

Started from "the scheduled CI is red every night" and ended up in the sandbox. Two of the four nightly failures were noise relative to this one:

| # | Failure | Outcome |
|---|---------|---------|
| 1 | `dependency-audit` died in `ensurepip` | **Fixed** `22b00a0e` — `uv run --with` → `uvx` |
| 2 | 18 real CVEs the never-running audit had been hiding | **Fixed** `22b00a0e` — `PyJWT>=2.15.0`, lock bumped, re-audit clean |
| 3 | `test_validation_report_is_deterministic` vs hardcoded `timeout(180)` | **Fixed** `22b00a0e` — cached consumers, 2 real passes kept |
| 4 | `test_fail_closed_policy_rejects_fallback` read `degraded` as "backend degraded" | **Fixed** `22b00a0e` — it is the 126/127 exit-ambiguity marker (WO5.0.0-019) |
| 5 | `test_sandbox_blocks_file_write`, red from a clean machine | **Honesty half fixed** `11843c98`; enforcement gap = this WO |

Finding #5 is what produced this workorder. It looked like a one-line flake and was not.

## Probe ledger — what was measured, and what it means

Every row was executed on this host (Linux, libseccomp present, **no landlock**, non-root) via `sandbox_run([...], allow_degraded=True)` against `default_policy()`. Re-run these before changing anything; the conclusions are load-bearing.

| # | Probe | Result | Reading |
|---|-------|--------|---------|
| P1 | `touch /tmp/x`, file **absent** | `isolation=syscall_policy` `verdict=ALLOW` `exit=0` file created | `/tmp/**` is an allowed write path — correct, not a bug |
| P2 | `touch /tmp/x`, file **present** | `verdict=KILL` `L3-SECCOMP-KILL` `exit=31` | `utimensat` is syscall-filtered. **This asymmetry is the whole flake** |
| P3 | `touch $HOME/.probe` | `verdict=ALLOW`, **file created** | seccomp enforces **no** write scoping. The real gap |
| P4 | grep `L3-FILE-W-001` description | `"Write to temp and stdio only"` | Overclaim: implies a deny-everything-else promise neither backend keeps |
| P5 | `_build_grants` (`landlock_backend.py:359-377`) | workspace granted `rw`; `/tmp/**` → anchor `/tmp` is an ancestor of workspace → **narrowed to workspace** (line 375); `/dev/null,/dev/stdout,/dev/stderr` are non-ancestors → granted | Landlock is **stricter** than the policy text implies |
| P6 | `_glob_anchor` on unbounded globs | `None` → `continue`; path-blind allow → `continue` ("ceiling: list paths") | Unbounded write grants refused outright |
| P7 | `grep -n 'def test_.*write' test_landlock_backend.py` | 4 hits (307/313/602/623) | **Landlock coverage already existed** — see Trap 2 |
| P8 | `test_sandbox_blocks_file_write` from clean `/tmp` | fails; with stale `/tmp/x` present, passes | Deterministic, not intermittent |

## Root cause

`L3-FILE-W-001` is written as a declarative path allowlist, but the field it populates is consumed by two backends with fundamentally different capabilities, and **neither implements it as written**:

- **seccomp-bpf cannot express it at all.** It filters syscalls; there is no path argument in the BPF program. `L3-FILE-W-001`'s paths are ignored (P3). It also blocks `utimensat` while permitting `open(O_CREAT)` (P2), so its observable file behaviour is an accident of syscall coverage, not policy.
- **landlock scopes by path but narrows.** Any allow-path that is an ancestor-or-equal of the workspace collapses to the workspace (P5, line 374-375), and unbounded globs / path-blind allows are dropped (P6). So `["/tmp/**", ...]` yields *workspace + the three stdio paths* — not "all of /tmp".

Net: under seccomp the effective write scope is **anything the kernel permits**; under landlock it is **workspace + stdio**. The policy text promises a third thing.

## Evidence (file:line, verified 2026-10-02)

- `policy.py:64-71` — `L3-FILE-W-001`, paths `["/tmp/**", "/dev/null", "/dev/stdout", "/dev/stderr"]`. `ceiling:` annotation at 56-66 now records P3/P5/P6.
- `landlock_backend.py:359-377` — `_build_grants` write branch: `grant(workspace_root, rw)` (363); path-blind allow refused (366-368); `_glob_anchor is None` skipped (370-372); ancestor-of-workspace narrowed (374-375); otherwise granted (377).
- `seccomp_backend.py:330` — `degraded=exit_code in (126, 127)`: the 126/127 ambiguity marker. Not the write story, but the same class of bug as finding #4 — a field whose meaning is backend-specific. `L3-SANDBOX-DEGRADE` is emitted only by `_fallback_run` (`seccomp_backend.py:512`).
- `tests/sandbox/test_landlock_backend.py:602` — `test_write_outside_workspace_gets_eacces`, real-exec, asserts non-zero exit + `Permission denied` on stderr + **file not created**.
- `tests/sandbox/test_landlock_backend.py:307,313` — `test_default_policy_has_no_bare_tmp_write`, `test_write_paths_tightened_to_workspace` pin the translation.
- `docs/manual.md:931,948,2580` — already disclose that landlock "enforces a fixed read-only/read-write path set that does **not** yet honor per-policy paths". This WO is the tracked version of that admission.
- `tests/sandbox/test_l3_sandbox.py:192` — removal-site comment naming all four landlock tests, so the seccomp test is not re-added.

## Landed in `11843c98` (do not redo)

- `L3-FILE-W-001.description` rewritten to state the grant-ceiling semantics, the landlock narrowing, and the seccomp non-capability. `rule_id`/`target`/`action`/`paths` untouched, so no policy signature or consumer moves.
- `TestSeccompBackend::test_sandbox_blocks_file_write` **retired, not relocated** — landlock covers the capability with stronger assertions, and the seccomp test's `KILL/DENY` expectation contradicted the event-driven verdict model (WO5.0.0-019: an EACCES block is enforcement, not a verdict, so it yields `ALLOW`).
- `fast` is now reproducible: **5965 passed / 37 skipped / 0 failed from a clean `/tmp`** (CI `37018167915` green at `b7ee7595`).

## Deliverables

1. **Decide the contract for `L3-FILE-W-001` under seccomp.** Options: (a) declare it landlock-only and have the seccomp path emit a startup/doctor warning that write scoping is unavailable — the honest, cheapest option; (b) synthesise a coarse seccomp approximation (e.g. deny `open` with `O_CREAT` outside the workspace via `SCMP_ACT_ERRNO`) and document it as *approximate*; (c) drop the paths from the default policy and let backend-specific policy fragments own them. (a) is the lazy correct answer; (b) is a real feature and needs its own threat model.
2. **Make `_build_grants` honour explicit non-workspace write paths** if (1) lands as (b) or (c) — today the ancestor-collapse at line 374-375 silently discards intent, with only a `logger.debug`.
3. **Stop calling the collapsed-ancestor case silent.** Line 375 and line 367 both `continue`/`grant` quietly; a policy asking for `/tmp/**` deserves at least a `logger.info` naming what it actually got.
4. **Test:** with `PICODOME_HAS_LANDLOCK=1`, a policy naming a writable path outside the workspace grants write there and still denies elsewhere. Must run in the `landlock-real-exec` CI job — it cannot be verified on this host.
5. **Keep `docs/manual.md` honest** — if the effective write scope stays "workspace + stdio" under landlock, say that in 931/948/2580 rather than only "fixed path set".

## Traps for whoever picks this up

1. **Clean `/tmp` before quoting any green fast-suite number.** `/tmp/seccomp_test_should_be_blocked` is now unreferenced by any test, but a stale copy makes a clean run and a dirty run disagree, and it silently flips write-path behaviour (P1 vs P2). `rm -f /tmp/seccomp_test_should_be_blocked` first. This cost two wrong conclusions in one session.
2. **Zero grep hits means wrong needle, not absence.** `grep 'file_write\|blocks_file_write' tests/sandbox/test_landlock_backend.py` returns nothing and looks like "landlock has no write coverage" — it does; the tests are named after *behaviour* (`test_write_outside_workspace_gets_eacces`). Use `grep -n 'def test_'` for structural listings. In a security product a false "this is covered" is worse than a false "this is missing".
3. **Landlock real-exec skips here.** 38 sandbox tests skip on this host. Any landlock claim is verified in CI or not at all — say which.
4. **CI never caught the misfiled test.** Runners degrade to `observational_only`, which hit the test's permissive branch. Do not read "green in CI" as "this path is exercised".
5. **`degraded` is backend-specific.** Before asserting on it, read every writer: `seccomp_backend.py:330` (126/127 ambiguity) vs `_fallback_run` (`L3-SANDBOX-DEGRADE`, real fallback). Same field, two meanings — finding #4 was exactly this.
6. **Do not re-add a seccomp file-write test.** It cannot be written honestly; see the removal-site comment at `test_l3_sandbox.py:192`.