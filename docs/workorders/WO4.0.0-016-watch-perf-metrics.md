# WO4.0.0-016 — Watch: scan performance + Prometheus hygiene

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** CLOSED-FOLDED (2026-08-18) — remainder (<1s/MB fused-pass restructure; not attempted, corpus-floor risk) moved to **WO5.0.0-029** (which also carries the load-sensitive perf-ceiling test flagged 2026-08-18). Landed & shipped in v2.1.2: metrics + freeze + hardening DONE; 4.88s → 1.75s per 200KB (2.8×, 8.8s/MB); sre-parse literal prefilter, decoded-payload byte budget, asyncio.to_thread + loop-freeze regression test, byte caps + body-limit middleware, single-source parser-validated metrics, bounded histograms, dropped-records gauge, admin rate limit + headers; corpus floors + determinism green
**Priority:** P1 · Effort M-L · Risk M (determinism must hold — corpus hash unchanged, `--verify-determinism` green)
**Scope:** `picosentry/watch/{prompt_guard/__init__.py,server.py}`, `picosentry/watch/telemetry/{sink.py,metrics.py}`, `tests/watch/`

**Gate:** `bash scripts/test.sh fast` + measured <1s/MB scan on the WO4.0.0-007 corpus + a Prometheus parser accepts /metrics output + loop-freeze regression test.

## Objective
Cut the 14–22s/MB guard scan to <1s/MB, stop the event-loop freeze, and make /metrics scrapeable.

## Evidence (measured + verified 2026-08-17)
1. 200KB benign → 2.8s (~14s/MB; comment-heavy 17; base64-heavy 22 — decode-rescan multiplies full normalize+evaluate per variant). `check()` runs inline in `async def` (server.py:230-252) → one large prompt freezes everything incl. /v1/health. No body cap before full JSON parse; `len(text)` counts chars not bytes (4× astral-plane).
2. `/metrics` emits INVALID exposition: sink renders `picowatch_requests_total` etc. from `_metrics`, then unconditionally appends `PrometheusMetrics.render()` which emits the SAME families again (sink.py:265-283, metrics.py:42-50) → duplicate HELP/TYPE, Prometheus rejects the scrape.
3. Histograms append every observation forever, render O(total) per scrape (metrics.py:28-33,63-87) — unbounded memory.
4. Admin app has no rate limit / security headers (server.py:344-425) — unthrottled key-guess surface.

## Deliverables
1. Literal/char-class prefilter (or single alternation pass) over the 59 rules; decode-rescan budget; `asyncio.to_thread` for check/validate; byte-based size caps reusing serve's RequestSizeLimitMiddleware pattern.
2. One source of truth for metrics (dedupe sink vs PrometheusMetrics); bounded histograms (fixed buckets); export `dropped_audit_records`.
3. Admin-app rate limit + security headers.
