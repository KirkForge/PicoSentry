# WO5.0.0-034 — Scan: OSV disk-cache round-trip decodes to empty (new, flagged during P0 wave)

**Series:** WO5.0.0 (new 2026-08-18 — verified by worker SA-Y while fixing WO5.0.0-009)
**Status:** DONE (2026-08-18, merge `c9dba832`, worker SA-AB) — cache stores raw OSV vuln records end-to-end, decode on read (new OSVClient._decode); round-trip + negative-entry tests. NEW verified bug fixed en route: offline queries wrote NEGATIVE entries to the shared disk cache (false-clean for 300s on later connected runs) — _fetch now returns None offline (WO4.0.0-006 guarantee extended).
**Owner:** (unassigned — worktree `wo/5.0.0/osv-cache-roundtrip`)
**Priority:** P1 · Effort S · Risk L
**Scope:** `picosentry/scan/intelligence.py`, `tests/scan/test_cache_correctness.py`

**Gate:** `bash scripts/test.sh fast` + round-trip test: OSV query → disk cache write → cache read (offline) → same advisories returned as the fresh query; negative entries still honored.

## Objective
The OSV cache must return what it stored — today every hit decodes to an empty list (false-clean on cached queries in connected mode).

## Evidence (verified 2026-08-18 during WO5.0.0-009 work)
`OSVClient._write_cache` stores `Advisory.to_dict()` shapes (intelligence.py:121-161) but `_read_cache` decodes via `from_osv` — the shapes don't round-trip, so every cache hit decodes to `[]`. The transport-failure no-negative-cache guarantee (WO4.0.0-006) is intact; this is the positive-path corruption. NOTE: WO5.0.0-009 changed `from_osv` to return `list[Advisory]` and updated the cache-read call site's shape handling — re-verify the exact broken pair on the MERGED tree before fixing (store OSV records or advisory dicts consistently end-to-end).

## Deliverables
1. Consistent store/parse round-trip (prefer caching the raw OSV response — the most future-proof shape).
2. Round-trip + negative-entry regression tests in test_cache_correctness.py.
