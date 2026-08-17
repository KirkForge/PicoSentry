# WO4.0.0-016 — Watch: scan performance + Prometheus hygiene

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** PARTIAL (2026-08-17, worktree `wo/4.0.0/scan-watch-p1`) — metrics + freeze + hardening DONE, perf gate NOT met. Measured on fixed 200KB benign buffer (time.monotonic, this worktree): 4.88s → 1.75s (24.4 → 8.8 s/MB, 2.8×); the <1s/MB target needs normalize+classifier restructured into single fused passes (not attempted — corpus-floor risk; remaining floor is ~2× normalize (~0.45s) + decode-rescan (~0.3s) + classifier (~0.35s) + ~10 full regexes). Landed: sre-parse-derived literal prefilter (sound necessary conditions; never joins literals across `\\s+` gaps — bug class covered by test; 59 rules → 7 always-run), decoded-payload byte budget (256KB/check), `asyncio.to_thread` for check+validate (loop-freeze regression test), byte-based caps + Content-Length body limit middleware, single-source metrics (dedupe; idle zero-export; parser-validated exposition), bounded fixed-bucket histograms (O(1)/series), `picowatch_dropped_audit_records` gauge, admin-app rate limit + security headers. Corpus floors + determinism green (358 watch tests).
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
