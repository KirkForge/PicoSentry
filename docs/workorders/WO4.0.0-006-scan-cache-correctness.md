# WO4.0.0-006 — Scan: cache correctness

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** DONE (verified 2026-08-17, shipped in v2.1.2 — cache key += config digest (cache.py:107-113) + bounded all-ecosystem input hashing (cli_service.py:55-75,178-189), OSV key += version + negative TTL (intelligence.py:30-32,60-67), pid-unique tmp names (cache.py:238, intelligence.py:127), HMAC keyfile precedence env→per-machine→per-process (cache.py:370-415) with mismatch/missing treated as miss (cache.py:196-203); 39 cache tests pass)
**Owner:** (unassigned — worktree `wo/4.0.0/scan-cache`)
**Priority:** P0 · Effort M · Risk M
**Scope:** `picosentry/scan/{cache.py,cli_service.py,intelligence.py}`, `tests/scan/{test_cache_governance.py,test_intelligence.py}`

**Gate:** `bash scripts/test.sh fast` + new tests: rules-filter cache miss, policy/config-change cache miss, non-lockfile-input invalidation, OSV version isolation, negative-cache hit, concurrent-write safety.

## Objective
The scan cache can serve wrong results and the OSV cache is version-blind — a security scanner must never mask a newly-malicious input.

## Evidence (verified 2026-08-17)
1. Scan-cache key = `(lockfile_hash, corpus_hash, __version__)` only (cache.py:106-108; cli_service.py:105-120). Ignores: `--rules` selection (`scan --rules X` after a full scan returns the full result); config/policy/baseline/severity filters (cached payload is a POST-filter snapshot, cli_service.py:170 vs 251-270); all non-lockfile inputs (modified `install.js`/`setup.py` doesn't invalidate — only npm/pnpm/yarn locks hashed). TTL 1h bounds the hazard; still real.
2. OSV `_cache_key` hashes `ecosystem:package` only (intelligence.py:56-57) but queries are version-filtered → upgraded dep gets the old version's advisories until TTL. No negative caching — every clean package re-queried (10s timeout each).
3. Concurrent writers race on a fixed tmp name (`.tmp` before `replace`) — cache.py:230, intelligence.py:110.
4. HMAC key process-random by default (cache.py:356-364): without `PICOSENTRY_CACHE_HMAC_KEY` every new process invalidates AND deletes all prior entries — persistent cache is a no-op by default.

## Deliverables
1. Cache key += rules-selection + config/policy digest; hash inputs for all 7 ecosystems (manifests, install scripts, setup.py).
2. OSV key += version; negative caching with short TTL.
3. Unique tmp names (pid) for concurrent writers.
4. HMAC default story: derive a stable per-machine key with explicit semantics (or documented always-fresh mode) instead of silent invalidate-on-read.
