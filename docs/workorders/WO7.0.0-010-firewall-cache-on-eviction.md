# WO7.0.0-010 — Firewall: VerdictCache O(n) eviction on every get/put (3.4ms/get at 10k entries)

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/firewall-cache-eviction`)
**Priority:** P1 · Effort S-M · Risk L
**Scope:** `picosentry/firewall/cache.py`, `tests/firewall/`

**Gate:** `bash scripts/test.sh fast` + test: 10k entries, get/put stays <0.5ms p99 (was 3.4ms); no full-scan eviction on every op.

## Objective
`_evict_expired` iterates ALL entries on every get/put. At 10k entries each op is 3.4ms — a proxy hot path that should be sub-millisecond.

## Evidence (verified 2026-08-20, explorer SA-watch; live measurement)
- `cache.py:32-33,49-50,65-66,74-80`: `_evict_expired` walks the entire dict on every `get`/`put`/`_set`.
- 10k entries → 3.4ms/get measured; cost grows linearly with cache size.

## Deliverables
1. Lazy eviction (expire-in-place on read of a stale entry) OR an expiry index (heap/OrderedDict keyed on expiry) so eviction is O(log n) or O(1) amortized.
2. Regression test per the gate (perf floor + correctness: expired entries still evicted).