# WO4.0.0-018 — Sandbox: L4 evidence pipeline + FP tuning

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** DONE 2026-08-17 (worktree `wo/4.0.0/sandbox-p1`) — evidence policy supersedes the old TestSpoofGuard contract (trade-off documented in profiler.py + test_profiler.py TestEvidencePolicy: kernel events with data win; text fills the address-less SCMP_ACT_LOG gap; text may add uncorroborated findings). DENIED_COMMANDS decision: wrappers (env/xargs/nohup/timeout/stdbuf) denied as entrypoints; interpreter-vs-L4-baseline split documented in daemon/constants.py. L4 per-rule docs: docs/rules/L4-RULES.md. Evidence: tests/sandbox/test_l4_fp_benign.py (benign corpus 0 CRITICAL), test_profiler.py, test_seccomp_trace_backend.py.
**Owner:** (unassigned — worktree `wo/4.0.0/l4-evidence`)
**Priority:** P1 · Effort M · Risk L
**Scope:** `picosentry/sandbox/l4/{profiler.py,detectors/*.py}`, `picosentry/sandbox/l3/backends/seccomp_trace/**`, `picosentry/sandbox/l4/differ.py`, `picosentry/sandbox/daemon/handler_mixins.py`, `picosentry/sandbox/docs/rules/` (add L4 docs)

**Gate:** `bash scripts/test.sh fast` + L4 fixture FP-rate test (target: benign corpus 0 CRITICAL) + evidence-extraction test on enforced backends.

## Objective
L4 must see real behavior on the backends that actually enforce, and stop flagging every benign postinstall.

## Evidence (verified 2026-08-17)
1. `profiler.py:90-96`: when a result has ANY events, network/fs/spawn extraction uses events only — which carry no addresses under SCMP_ACT_LOG — and seccomp-trace always appends a lifecycle event → trace/seccomp runs lose stdout-derived evidence exactly when SUS/timeout events fire. L4-EXFIL/NET/CRYPTO/DEP see an empty profile on enforced backends.
2. `differ.py:45-53` compares raw URLs against domain allowlists — never equal → guaranteed "unexpected domain" drift for benign npm.
3. FP catalog: chmod→CRITICAL (honeypot.py:42-54, every benign postinstall), <5ms→MEDIUM (timing.py:11), `.sh` outside /tmp→MEDIUM (filesystem.py:71-89, npm shims), >5 spawns→MEDIUM (process_anomaly.py:73), `--registry=`→HIGH (dependency_confusion.py:137-148), endswith persistence match (persistence.py:36).
4. DENIED_COMMANDS contradicts the product: `env/xargs/find/awk/sed/git/tar/timeout` NOT denied (`env bash -c …` sails through) while `node/python` ARE denied — L4 node/python-script baselines can never fire via the daemon (handler_mixins.py:143-189).
5. seccomp vs seccomp-trace default-action divergence (filter_builder.py:27-30 vs seccomp_backend.py:337-340): same permissive policy → opposite verdicts per backend.

## Deliverables
1. Profiler merges event- AND stdout-derived evidence (event address empty → fall through to regex).
2. URL-vs-domain matching fix; FP reclassification round (categories above).
3. DENIED_COMMANDS policy decision (align with L4 baselines or document the split).
4. seccomp-trace default-action parity; per-rule L4 docs (L3 has them, L4 doesn't).
