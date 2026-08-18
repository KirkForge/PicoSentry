# WO6.0.0-017 — Firewall: VerdictCache not thread-safe + `%40`-encoded scope misclassification

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/firewall-cache-scope`)
**Priority:** P1 · Effort S-M · Risk L
**Scope:** `picosentry/firewall/{cache.py,scanner.py,proxy.py}`, `tests/firewall/`

**Gate:** `bash scripts/test.sh fast` + tests: concurrent get/put/evict stress (8 threads × 3000 ops) zero errors; `%40scope/pkg` classified and scanned identically to `/@scope/pkg`.

## Objective
Two firewall robustness/correctness holes found post-WO5-012.

## Evidence (verified 2026-08-18, explorer SA-AS; live repros t8/t9)
1. **VerdictCache unsynchronized** (`cache.py:27-47,64-68`): plain dict iteration/deletion under ThreadingHTTPServer. Live: 8 threads × 3000 get/put → 5 errors (`RuntimeError: dictionary changed size during iteration`, KeyError) — handler thread dies mid-request.
2. **`%40` scope** (`scanner.py:19,76`): `/%40scope/pkg` classifies as npm name `%40scope` (not decoded); upstream decodes to the real `@scope/pkg` catalog; `extract_version_manifest` falls back to the CATALOG ROOT — the version-manifest finding (postinstall script) is never scanned → ALLOW where `/@scope/pkg` would QUARANTINE.

## Deliverables
1. `threading.Lock` around get/put/evict (RateLimiter's pattern).
2. Percent-decode the path before `_NPM_PACKAGE_RE` (unquote `%40` like `%2F` already is); unresolvable version → 400/502 instead of root-manifest fallback.
