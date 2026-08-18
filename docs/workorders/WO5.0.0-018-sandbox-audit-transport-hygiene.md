# WO5.0.0-018 — Sandbox: audit & transport hygiene sweep

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/sandbox-hygiene`)
**Priority:** P1 · Effort M · Risk L
**Scope:** `picosentry/sandbox/audit/logger.py`, `picosentry/sandbox/grpc_transport/{client.py,_servicer.py}`, `picosentry/sandbox/daemon/{handler.py,handler_routes_get.py,handler_routes_post.py}`, `picosentry/sandbox/policy_versioned/{store.py,signing.py}`, `picosentry/sandbox/l3/backends/subprocess_backend.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + new tests: `/api/v1/audit?limit=3` returns the 3 most recent events; gRPC client refuses plaintext non-loopback targets; QueryAudit limit clamped.

## Objective
Small correctness/hygiene defects batched: audit recency, gRPC hardening, shared-code dedup, state bugs.

## Evidence (verified 2026-08-18, explorer SA-S; live repros or airtight chains)
1. **Audit `query()` returns the OLDEST window** (MEDIUM): `audit/logger.py:236-285` forward scan, break at limit, then `results.reverse()` — live: daemon with ~12 events, `limit=3` returned the three oldest in "newest-first" dressings. Every paginating consumer sees stale history.
2. **gRPC client silently downgrades to plaintext for ANY target and still sends the Bearer token** (LOW): `grpc_transport/client.py:92-97` — no client-side counterpart of server-side `assert_secure_transport` (`auth.py:77-89`). Token disclosure to wrong/hostile endpoints.
3. **gRPC `QueryAudit` limit unclamped** (`_servicer.py:231`) vs HTTP's `_clamped_limit` (1000) → whole-file scan; `_servicer.py:88-89` `_scan_count += 1` unsynchronized (HTTP uses `_stats_lock`).
4. **`_check_cluster_token` duplicated verbatim** in `handler_routes_get.py:23-59` and `handler_routes_post.py:33-69`, with drifted exception tuples (GET catches ValueError/TypeError/AttributeError on audit failure, POST doesn't) — dedup into one shared helper.
5. **`PicoDomeHandler._start_time` is a class attribute** (`handler.py:49`) — uptime/metrics report time since first import, not daemon start.
6. **Token-file permission check warns but claims "Reject"** (`auth.py:124-137`) — world-readable token file loads anyway; brute-force backoff keyed by hash of the *tried* token, so rotating guesses never accumulates.
7. **Policy store dir env split-brain**: `policy_versioned/store.py:26` freezes `PICODOME_POLICY_STORE_DIR` at import while `l3/policy.py:254-255` reads it at call time — save/load can target different dirs; `monkeypatch.setenv` after import writes to the real `~/.picodome/policies`.
8. **Verdict inconsistency for signal deaths**: subprocess returns ALLOW for signal-killed children (exit −11, no events) while seccomp returns KILL for exit −1.
9. **`VersionedPolicyStore.save` version race**: two threads compute the same `next_version`, silent overwrite via atomic write.
10. Unverified suspicion to close out: gRPC manual fallback (`add_servicer_manually` + `_do_scan_manual`) likely cannot work end-to-end (identity deserializer hands raw bytes to the servicer; `_DictProxy` responses would fail serialization) — verify and either fix or delete.

## Deliverables
Fixes for each item; shared helpers where noted; regression tests per the gate.
