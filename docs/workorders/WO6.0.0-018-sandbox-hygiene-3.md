# WO6.0.0-018 — Sandbox: hygiene round 3 (audit archives, reserved policy names, health truth, /ready forks, redis reads, riders)

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/sandbox-hygiene-3`)
**Priority:** P1 · Effort M · Risk L
**Scope:** `picosentry/sandbox/audit/logger.py`, `picosentry/sandbox/{policy_versioned/store.py,l3/policy.py}`, `picosentry/sandbox/health.py`, `picosentry/sandbox/daemon/{handler_routes_get.py,redis_store.py}`, `picosentry/sandbox/tenant/store.py`, `picosentry/sandbox/l3/engine.py`, `picosentry/sandbox/constants.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + tests: rotated-archive query returns full history (or an honest truncation marker); reserved policy name rejected at save; health reports the redis backend truthfully; negative timeout rejected at the entry points.

## Objective
Batch of verified sandbox defects (explorer SA-AQ, all live-repro'd or airtight).

## Evidence (2026-08-18)
1. **Audit query/get_stats blind to rotated archives** (MED-LOW): `logger.py:223-288,290-315` read only the live file — 60 events with rotation → `query(limit=1000)` returns 3, `get_stats().events` = 3, while `verify_chain` walks archives (data exists, chain-verified). Truncated window presented as whole history.
2. **Reserved policy names silently shadowed** (MED): `policy.py:269-278` named-policy short-circuit BEFORE the store read → stored "default"/"strict"/"node"/"python" policies persist, version, sign, display — and never load on scans. Live: saved `default` v9.9 allow; scans run builtin deny.
3. **Health lies under redis** (MED-LOW): `health.py:129-151` special-cases sqlite only → `PICODOME_STORE_BACKEND=redis` reports `backend=jsonl healthy=True` even with Redis down.
4. **/ready re-probes backends per request** (LOW-MED): `handler_routes_get.py:199-202` bypasses the caching registry → `os.fork()` inside a ThreadingHTTPServer worker per request (probe_log_emits, `process_manager.py:100-129`) — cacheable fork hazard.
5. **`probe_log_emits` is vacuous** (LOW): returns `WIFEXITED or WIFSIGNALED` — true for any reaped child; never detects non-emission (the availability gate can't gate).
6. **Redis outage reads masquerade as not-found** (LOW): `redis_store.py:157-167,201-215` return None/[] when unavailable → API 404/"count: 0" during an outage (writes correctly 503 since WO5-017).
7. Riders: `list_recent` hardcoded inner limit 1000 (`tenant/store.py:85`, no ceiling note); audit `since`/`until` raw string compares (`logger.py:261-264` — parse-or-reject); `sanitize_scan_timeout` accepts negative finite (`constants.py:161-173` → landlock deadline instantly past: honest KILL but should be a 400); negative grace values parse (fold with WO6-014 if same worker).

## Deliverables
Fix each; archive-aware query (deque over `_rotated_archive_paths`) or explicit `{truncated: true, archives: N}`; reserved names rejected at save; redis health branch; /ready through the registry; probe renamed/fixed; redis reads raise/flag; riders.
