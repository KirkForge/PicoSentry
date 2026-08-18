# WO6.0.0-019 — Scan: corpus-index memory governance + GO keyboard ceiling + riders

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/corpus-memory`)
**Priority:** P1 · Effort M · Risk M (index correctness is pinned — extend, don't redesign)
**Scope:** `picosentry/scan/rules/{corpus_index.py,typosquat.py}`, `picosentry/scan/engine.py`, `picosentry/scan/cli_service.py`, `tests/scan/`

**Gate:** `bash scripts/test.sh fast` + tests: `_index_cache` evicts stale-mtime entries on corpus update (bounded RSS across update cycles); prewarm cost halved on detected-ecosystem-only scans; GO keyboard ms/dep pinned by a slow-tier perf test; advisory-dir digest in the cache key.

## Objective
WO5-028's index landed with npm-only cost documentation — the all-ecosystem reality is ~3× worse, and the cache never evicts.

## Evidence (2026-08-18, explorer SA-AP; live measurements)
1. **Aggregate prewarm cost**: npm 3.07s/+124MB · pypi 2.91s/+94MB · go 1.60s/+69MB · cargo 0.26s/+7MB · maven 1.18s/+34MB · nuget 1.94s/+79MB · rubygems 0.13s/+5MB → **~412MB / ~11s** for a polyglot dep-heavy repo, all outside any timebox. Documented ceiling names only npm ~150MB.
2. **`_index_cache` never evicts** (`corpus_index.py:18`): key includes mtime/size → every on-disk corpus update (`picosentry update`, separate process) makes the long-lived daemon build AND retain a NEW index while the old stays strongly referenced → O(412MB) growth per update cycle.
3. **Prewarm ignores detection**: `prewarm_typosquat_indexes` probes all 7 ecosystems; `_detected` is already computed in `scan()`.
4. **GO keyboard path always trie** (`corpus_index.py:174` — keyboard ⇒ no SymSpell): measured 2.3s/420 deps = 2.2× headroom under the 5s box on THIS hardware; CI runners slower; ~800+ modules silently drop findings (the SA-AJ timebox class).
5. Riders: default advisory dir not in the scan-cache key (`cli_service.py:159` — `advisories fetch` doesn't invalidate; TTL-bounded stale); `rule_executions[].findings_count` reports the group total per sub-rule alias (`engine.py:544-552`) vs `stats.findings_by_rule` from actual findings; parity test forces agreement by passing priority_names=corpus (production priority differs — a future guard change can silently diverge).

## Deliverables
1. Aggregate ceiling docs + `_index_cache` stale-entry eviction + detected-only prewarm.
2. GO keyboard: `ponytail:` ceiling with the ms/dep measurement + slow-tier perf pin (or dep-count threshold fallback to non-keyboard matching).
3. Riders (advisory-dir digest; per-sub-rule attribution; production-config parity test).
