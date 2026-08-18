# WO5.0.0-024 — Watch: metrics/telemetry honesty sweep (family render, edge hardening)

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/5.0.0/watch-metrics`)
**Priority:** P1 · Effort M · Risk L
**Scope:** `picosentry/watch/telemetry/{metrics.py,otel.py,sink.py}`, `picosentry/watch/{server.py,gateway.py,prompt_guard/rules.py}`, `picosentry/watch/output_guard/__init__.py`, `picosentry/watch/scorer.py`, `tests/watch/`

**Gate:** `bash scripts/test.sh fast` + new tests: exposition with two `model` labels parses (one HELP/TYPE per family); zero-rule tenant profile refused/warned; chunked-TE body rejected at cap; XFF-derived client IP is the proxy-visible one.

## Objective
Batch of watch correctness/honesty items: valid exposition under labels, edge-deployment hardening, dead-surface cleanup.

## Evidence (verified 2026-08-18, explorer SA-U; live repros)
1. **/metrics invalid the moment a `model` label appears** (HIGH): `render()` emits HELP/TYPE per series, not per family (`telemetry/metrics.py:70-88`); pre-registration (`sink.py:44-52`) guarantees the unlabelled series, so two POSTs with `context.model` "gpt-4o"/"claude-3" → 3× HELP + 3× TYPE for `picowatch_requests_total` — Prometheus rejects the whole scrape. WO-016's validator test never records a scan with `details.model`.
2. **Tenant profile with a zero-matching category set silently disables all rules**: typo'd `allowed_categories` → `rules_loaded == 0`; the zero-rule guard only fails closed when `config.fail_closed` (default False); verdicts still report the full-corpus `corpus_hash` (`gateway.py:128-133`, `prompt_guard/rules.py:198-203,215-219`, `prompt_guard/__init__.py:73`).
3. **XFF trusts the first (client-forgeable) entry** when `PICOWATCH_TRUST_PROXY=1` (`server.py:72-79`): behind standard nginx the first entry is client-supplied → rotating forged XFF values = fresh rate-limit buckets. Take the last entry or make trusted-hop count configurable.
4. **Body-size middleware is Content-Length-only** (`server.py:88-106`): chunked TE skips the pre-parse cap; starlette buffers the whole body before the handler's byte check. The docstring's promise is bypassable.
5. **OTel spans never carry the audit request_id**: `otel.py:101` reads `result.details.get("request_id")` but `server.py:291` never injects it — correlation claimed, always "".
6. **Redaction misses NFKC-foldable obfuscation**: rules evaluate normalized text (fullwidth `ｐｏｓｔｇｒｅｓ://…` flags invalid) but `_detect_pii` runs on raw text (`output_guard/__init__.py:99-109`) → the `redacted` copy still contains the obfuscated secret.
7. **Scorer dead computation**: `scorer.py:33` `max(max_score, avg_score)` — avg of weights can never exceed max; always `max_score`.
8. **Dual-unit export confusion**: `picowatch_scan_duration_ms_sum` (counter, ms) alongside `_seconds` histograms of the same quantity; `prompt_score_sum` counter with no matching count family.

## Deliverables
Fixes per item: family-grouped render, zero-rule refusal + `rules_loaded` in metadata, XFF policy, streamed byte counting, request_id wiring, normalized-text redaction pass, scorer simplification, metric naming cleanup.
