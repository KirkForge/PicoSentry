# WO5.0.0-023 — Watch: gateway production hardening (loop, body, auth, streaming ceiling)

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/gateway-hardening`)
**Priority:** P1 · Effort M · Risk M
**Scope:** `picosentry/watch/{gateway.py,server.py}`, `tests/watch/`

**Gate:** `bash scripts/test.sh fast` + new tests: 200KB prompt through the gateway doesn't stall the loop (concurrent request completes); oversized body → 413 before buffering; unknown API key → 401; prompt char-cap counts bytes not chars.

## Objective
The WO-023 gateway shim must not reintroduce the exact classes WO-016 fixed in server.py.

## Evidence (verified 2026-08-18, explorer SA-U; live measurement + code chains)
1. **CPU-bound guards synchronously on the loop**: `gateway.py:220,268` — `guard.check(prompt_text)` direct sync call in `async def` (server.py uses `asyncio.to_thread` at `:281,341`). Measured 1.51s for a 200KB benign prompt (~7.5s at the 1M-char internal cap).
2. **No body cap, no rate limit, no auth, no security headers**: `create_gateway_app` has none of `create_app`'s middleware/dependencies; probes reached it with no API key at all — unknown keys silently get the default profile (`gateway.py:135-138`).
3. **Char-based size cap**: `prompt_guard/__init__.py:85` `len(text)` while the message claims bytes — astral-plane text quadruples the effective budget.
4. **"Streaming" fully buffers**: `_forward` uses `await client.request(...)` (whole body read) and the stream branch returns `Response(content=forwarded.body)` as one blob (`gateway.py:140-172,242-254`) — client receives the "stream" only after upstream completes; memory unbounded (contrast firewall's 512MB cap-and-close). Docstring annotates *unscanned* output but not *destroyed streaming delivery*.

## Deliverables
1. `to_thread` both guard calls; reuse `_body_size_limit` + `_verify_api_key` + rate limiter; byte-based size check.
2. Document the buffering ceiling in the docstring/response header now; true chunked passthrough is the upgrade path (the `scan_stream_chunk` reassembly-buffer design note already sketches it).
