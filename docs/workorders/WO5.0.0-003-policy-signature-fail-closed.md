# WO5.0.0-003 — Sandbox: policy signature verification fails OPEN without a key

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/policy-sig`)
**Priority:** P0 · Effort S · Risk M
**Scope:** `picosentry/sandbox/policy_versioned/signing.py`, `picosentry/sandbox/l3/policy.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + new test: signed policy + tampered on disk + key absent on verifier → `load_policy(verify_signature=True)` raises (fail-closed).

## Objective
A *signed* policy that cannot be verified must be rejected, not loaded. Tamper-evidence must not silently disable itself on misconfiguration.

## Evidence (verified 2026-08-18, explorer SA-S; live repro)
`signing.py:334-337`: `has_sig and effective_key is None` → returns full content with `VerifyResult(valid=False)`. `l3/policy.py:293-296`: rejection condition is `if not content and result and not result.valid` — misses the branch where content is non-empty. Live: policy signed with key K, file tampered (network_out DENY→ALLOW), key unset on verifying host → `load_policy(name="demo", verify_signature=True)` **loaded the tampered policy**; log only "loading without verification". The daemon scan path calls exactly this API (`handler_routes_post.py:189`).

## Deliverables
1. `load_policy` rejects whenever `result is not None and not result.valid`.
2. Enterprise mode: require a configured key entirely (refuse signed-policy loading without one).
3. Regression test as in the gate.
