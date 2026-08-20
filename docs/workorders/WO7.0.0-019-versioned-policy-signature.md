# WO7.0.0-019 — Sandbox: versioned policy loads skip signature verification (only `latest.json` is signed)

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/versioned-policy-sig`)
**Priority:** P1 · Effort S · Risk M
**Scope:** `picosentry/sandbox/policy_versioned/{store.py,signing.py}`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + test: loading a `vN.json` whose `.sig` is missing or tampered raises (default verify); `policy_versions show --version N` verifies before display.

## Objective
`sign_policy_companion` writes a `.sig` for `latest.json` only; `VersionedPolicyStore.load` doesn't verify; `policy_versions show --version N` displays with no signature check. A versioned policy file is a tamper target with no defense.

## Evidence (verified 2026-08-20, explorer SA-sandbox; file:line chain)
- `signing.py:249-265`: `sign_policy_companion` writes `.sig` for `latest.json` only.
- `store.py:141-156`: `VersionedPolicyStore.load` reads `vN.json` without verifying any signature.
- CLI `policy_versions show --version N` reaches `load` with no verify flag.

## Deliverables
1. `sign_policy_companion` signs `vN.json` too (one `.sig` per file).
2. `load` accepts a `verify_signature` param (default True) and verifies against the matching `.sig`.
3. CLI `show --version N` verifies before display.
4. Regression test per the gate.