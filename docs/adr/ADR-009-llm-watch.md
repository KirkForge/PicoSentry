# ADR-009: LLM Watch subsystem (PicoWatch)

**Status:** Accepted
**Date:** 2026-08

## Context

PicoSentry's LLM defense layer — the `picosentry/watch/` package, product name
**PicoWatch** — had no architecture decision record. It is a distinct subsystem
from the L2 static scanner and the L3/L4 kernel sandbox: it defends the *model
interaction boundary* (prompt in, output out) rather than the package install
boundary. It is the terminal layer in the cross-layer correlation chain
(`scan → sandbox → watch`), so its trust model, fail-closed behavior, and
observability contract need to be pinned down.

The subsystem is a FastAPI service with four cooperating components:

- **Prompt guard** (`prompt_guard/`) — detects prompt-injection on the way in.
- **Output guard** (`output_guard/`) — validates/redacts model output on the way out.
- **Telemetry** (`telemetry/`) — Prometheus metrics + OpenTelemetry tracing + an
  HMAC-checksummed SQLite audit log.
- **Server** (`server.py`) — the HTTP surface, rate limiting, auth, health.

## Decision

**PicoWatch is a deterministic, offline, fail-closed LLM defense service.** The
four components are composed in `create_app()` and share a single
`PicoWatchConfig` (a delegating dataclass that routes attribute access to
`PromptGuardConfig` / `OutputGuardConfig` / `TelemetryConfig` / `ServerConfig`).

### Prompt guard

- **Rule engine first, deterministic classifier second.** `RuleEngine` loads
  YAML rules from `rules/prompt_injection/` (6 families: context injection,
  encoding attack, extraction attempt, instruction override, multi-turn trap,
  role manipulation), compiles them to regexes, and hashes the corpus
  (`corpus_hash`) for reproducibility. `PromptClassifier` is a *deterministic
  lexical* scorer (not a learned model) that blends with the regex score and can
  only **elevate**, never lower, it (`blend()` = `max(regex, classifier * factor)`).
- **Normalization before evaluation.** `Normalizer` applies NFKC unicode
  normalization, whitespace collapse, comment stripping, and deobfuscation
  (base64 / ROT13 / URL-encoding / zero-width chars) before the rules run, and
  re-scans decoded variants.
- **Fail-closed.** If the rule corpus fails to load entirely, or evaluation
  throws, the request is blocked (`fail_closed_no_rules` / `fail_closed_error`)
  rather than allowed through. This is the security-critical default posture.

### Output guard

- **Schema validation + policy rules + PII redaction.** Validates output against
  an optional JSON schema (with `SchemaTooLargeError` guarding pathological
  schemas via `max_json_schema_nodes` / `max_json_schema_depth`), evaluates
  `rules/output_policy/` (exfiltration, format violation, harmful content, PII
  leak), and redacts secrets (SSH keys, JWTs, DB URLs, OAuth tokens, AWS ARNs,
  API keys, credit cards, SSNs, passports, crypto wallets, internal URLs, env
  vars, emails, phones).
- **Feedback loop.** A prior prompt-scan result with score ≥ 0.4 amplifies the
  output score (×1.3), linking the two guards.

### Telemetry

- **Prometheus** counters/histograms for requests, blocks, scores, durations.
- **OpenTelemetry** spans (`picowatch.prompt_guard.scan`,
  `picowatch.output_guard.validate`) when `PICOWATCH_OTEL_ENDPOINT` is set;
  tracing is a no-op when the deps are absent (offline-safe).
- **Audit log** in SQLite (`picowatch_audit.db`), each row HMAC-SHA256
  checksummed with `PICOWATCH_AUDIT_HMAC_KEY` so tampering is detectable via
  `verify_audit_integrity()`. Retention is `PICOWATCH_AUDIT_RETENTION_DAYS`.

### Server

- **Two apps.** `create_app()` (main, port 8766) and `create_admin_app()`
  (read-only health/metrics/rules, port 9091, run on a daemon thread).
- **Auth.** API key via `X-API-Key` header or `Authorization: Bearer`, compared
  with `secrets.compare_digest`. No key in query strings (per the repo's
  websocket-auth convention).
- **Rate limiting.** Per-IP sliding window (`RateLimiter`, default 100 req/min),
  with a bounded client table to resist memory-exhaustion DoS. Health is exempt.
- **Security headers** (`nosniff`, `DENY` framing, strict referrer) and
  `Cache-Control: no-store` on scan endpoints.
- **Secure boot.** `assert_secure()` refuses to bind `0.0.0.0` without an API
  key and rejects short keys; config file permissions are checked.

## Rationale

- **Determinism + offline** are the product's core guarantees (ADR-001). The
  classifier is deliberately not a learned model, and OTel is a no-op without
  deps, so PicoWatch reproduces identically in an air-gapped environment.
- **Fail-closed** is the correct default for a security boundary: a guard that
  silently passes everything on error is worse than one that blocks.
- **HMAC audit checksums** make the audit log tamper-evident, which matters
  because the watch layer is the terminal correlation layer — its findings feed
  kill-chain scoring and escalation.
- **Classifier can only elevate** prevents the classifier from regressing
  existing regex detections while still catching paraphrased overrides.

## Consequences

- New prompt/output rules are data (YAML under `rules/`), not code — adding a
  detection does not require a release.
- The audit DB (`picowatch_audit.db`) is runtime state and must not be
  committed (it is gitignored).
- `PICOWATCH_AUDIT_HMAC_KEY` must be set for persistent audit verification;
  without it the key is random per-process and checksums do not survive restarts.
- The watch layer is terminal in cross-layer correlation: `_AUTO_ANALYSIS_MAP`
  in the correlation engine routes `scan → sandbox → watch` and stops there.
