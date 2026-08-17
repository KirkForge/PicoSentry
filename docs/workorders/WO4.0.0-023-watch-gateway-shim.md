# WO4.0.0-023 — Watch: API-compat gateway shim (prototype)

**Series:** WO4.0.0 (exploration round 2026-08-17)
**Status:** DONE (prototype scope, 2026-08-17, worktree `wo/4.0.0/scan-watch-p1`) — `picosentry/watch/gateway.py`: OpenAI-compatible `POST /v1/chat/completions` passthrough (httpx, lazy import, injectable client for tests); prompt scan BEFORE forward (blocked prompt never reaches upstream, 400 with `picowatch` metadata: verdict, score, rules, explanations with rule id + match span); output validated on the non-streaming response with metadata + optional `block_on_output_violation`. Streaming: full prompt scan + honest pass-through (`X-Picowatch-Output-Scanned: false`, `scan_stream_chunk` stub documents the chunk-boundary ceiling). Per-tenant profiles: `TenantProfile(allowed_categories, threshold_block)` selected by gateway API key (RuleEngine gained `allowed_categories`; profile threshold override copies the sub-config so it cannot leak into other profiles). Tests: tests/watch/test_gateway.py (5). Not built (documented in module docstring): retries, routing, usage rewriting, non-chat endpoints.
**Priority:** P2 · Effort L · Risk M (scope creep — prototype minimal first)
**Scope:** `picosentry/watch/` (new shim module), reuses prompt_guard/output_guard

**Gate:** prototype: OpenAI-compatible `/v1/chat/completions` passthrough with prompt+output scanning, streaming-scan hook stubbed + documented; per-tenant policy profiles; verdict explanations (rule id + match span) in the response metadata.

## Objective
The product story: drop-in LLM gateway mode. Prototype the minimal shim first; do not build the full proxy.

## Evidence (exploration 2026-08-17)
Product-gap analysis: watch scans standalone prompts/outputs but has no API-compat mode — adoption requires sitting between app and provider. Streaming responses cannot be scanned today (output guard is whole-text). No per-tenant policy profiles; verdicts lack analyst-facing explanations (rule + match span). Politeness-suppression and paraphrase gaps (classifier capped ×0.6 below block by benign markers; regex misses paraphrases) argue for the explanation surface so analysts can tune.

## Deliverables
1. Minimal OpenAI-compatible shim (passthrough + guards, non-streaming first).
2. Streaming-scan hook: design + stub with documented ceiling.
3. Per-tenant policy profiles (rule-set selection per API key) + verdict explanations in metadata.
