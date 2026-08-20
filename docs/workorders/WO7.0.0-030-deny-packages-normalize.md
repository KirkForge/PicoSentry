# WO7.0.0-030 — Scan: `deny_packages` policy comparison case-sensitive and not PEP 503 normalized

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/deny-packages-normalize`)
**Priority:** P2 · Effort S · Risk L
**Scope:** `picosentry/scan/policy_pkg/engine.py`, `tests/scan/`

**Gate:** `bash scripts/test.sh fast` + test: `deny: ["flask"]` matches an installed `Flask` and `Flask-Pytest` (normalized compare); no FP on `flask-thing`.

## Objective
`d_name == pkg_name` with no normalization — `deny 'flask'` won't catch installed `Flask`. Case + PEP 503 normalization both missing.

## Evidence (verified 2026-08-20, explorer SA-scan; file:line chain)
- `engine.py:189-209`: the comparison is a direct string equality; no `.lower()`, no PEP 503 normalize (dot/underscore → dash).

## Deliverables
1. PEP 503-normalize both sides before the compare (stdlib `packaging.utils.canonicalize_name` or inline).
2. Regression test per the gate.