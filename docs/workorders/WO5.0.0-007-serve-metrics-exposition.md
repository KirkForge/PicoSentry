# WO5.0.0-007 — Serve: /metrics/prometheus exposition invalid (duplicate samples + label injection)

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** DONE (2026-08-18, merge `4a5cad75`, worker SA-X) — render-time aggregation by full label set (one sample/series; counters/gauges latest-wins, histograms summed); `_LABEL_UNSAFE` sanitizer at `api_request` + single-source escaped renderer (watch's approach); api families exempt from the org filter in both exporters with upgrade-path comment (per-request org stamping); strict-parser tests: zero duplicates under repeated increments, the exact injection repro path injects nothing, org views keep api series. Mutation-verified (3/4 tests fail on unfixed code).
**Owner:** (unassigned — worktree `wo/5.0.0/serve-metrics`)
**Priority:** P0 · Effort M · Risk M
**Scope:** `picosentry/serve/services/metrics.py`, `picosentry/serve/middleware/audit.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + new tests: exposition parses with zero duplicate series under repeated increments; a path containing `"}\n# HELP` injects nothing.

## Objective
Serve needs the WO4.0.0-016 treatment watch got: one sample per series, escaped labels, no unauthenticated injection vector.

## Evidence (verified 2026-08-18, explorer SA-T; live repros)
1. **Duplicate samples per series**: `metrics.py:140-145` renders every stored `Metric` (one appended per increment, `metrics.py:44-67`) → identical label sets appear up to 50× per scrape; Prometheus rejects duplicate samples. Live: 3 identical `api_requests_total{...}` lines in one render.
2. **Label injection**: label values interpolated with no escaping (`metrics.py:141`); the endpoint label is the request's percent-decoded path fed by `AuditMiddleware.dispatch` (`middleware/audit.py:198`, outermost, unauthenticated included). Live: path `/api/v1/x"}\npicoshogun_fake_total 999\n# HELP injected` produced arbitrary injected exposition lines — visible in every org's filtered view (injected labels carry no org_id → pass the org filter at `metrics.py:128`).

## Deliverables
1. Render-time aggregation by label set (one sample per series).
2. Escape/validate label values at `api_request`; sanitize path labels.
3. Org-label decision for api metrics (today org-filtered views hide api series entirely — `metrics.py:154-158` filters on a label `api_request` never sets).
4. Exposition validated by a parser test (port watch's approach).
