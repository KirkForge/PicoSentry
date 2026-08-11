# ADR-009: LLM watch subsystem (PicoWatch)

**Status:** Accepted
**Date:** 2026-08

## Context

Applications that call LLM APIs need defense against prompt injection on the
way in and data exfiltration / policy violations on the way out. The watch
subsystem (`picosentry/watch/`) is that defense: a standalone, self-contained
LLM guard with its own HTTP server, rule corpus, telemetry, and audit trail.
It must be deterministic, offline-capable, and fail closed when the guard
itself cannot evaluate.

## Decision

**PicoWatch is a deterministic, rule-based LLM guard with a FastAPI server,
split into a prompt guard and an output guard, plus telemetry and rate
limiting.**

- **Prompt guard** (`picosentry/watch/prompt_guard/`): `PromptGuard.check()`
  normalizes the input (`Normalizer`), evaluates it against a rule corpus
  (`RuleEngine`), re-scans decoded/obfuscation variants, scores matches
  (`Scorer`), and optionally blends in a `PromptClassifier` score. It returns
  a `PromptScanResult` with a `blocked` verdict, score, matched rules, and
  corpus hash/version. It is fail-closed: if the rule corpus failed to load
  entirely, or evaluation raises, it returns `blocked=True` rather than
  allowing the prompt through.
- **Output guard** (`picosentry/watch/output_guard/`): `OutputGuard.validate()`
  checks LLM output against an output-policy rule corpus, optional JSON
  schema (with size/depth limits via `_check_schema_size` to reject
  pathological schemas), and a PII/secret redaction pass (`_detect_pii`) that
  flags and redacts SSH keys, JWTs, DB URLs, OAuth tokens, AWS ARNs, API keys,
  credit cards, SSNs, passports, crypto wallets, internal URLs, IPs, env vars,
  emails, and phones. It returns a `ValidationResult` with `valid`, score,
  violations, and redacted text.
- **Server** (`picosentry/watch/server.py`): `create_app()` exposes
  `POST /v1/scan/prompt` and `POST /v1/scan/output` (both size-limited and
  fail-closed on evaluation error), plus read-only `GET /v1/health`,
  `GET /v1/rules`, `GET /v1/rules/{id}`, and `GET /metrics`. A separate
  `create_admin_app()` runs read-only health/metrics/rules on a distinct
  admin port. Auth is a shared API key compared with `secrets.compare_digest`;
  when no key is configured, write endpoints are unauthenticated (test mode).
- **Rate limiting** (`picosentry/watch/ratelimit.py`): a per-IP sliding-window
  `RateLimiter` with a bounded client table (`max_clients`) that evicts stale
  entries and denies new clients at capacity to prevent memory-exhaustion DoS.
  Health checks are exempt.
- **Telemetry** (`picosentry/watch/telemetry/`): `TelemetrySink` records every
  scan to a SQLite `picowatch_audit.db` with an HMAC-SHA256 `checksum` per row
  (keyed by `PICOWATCH_AUDIT_HMAC_KEY`, falling back to a per-process random
  key), exposes Prometheus metrics, and enforces audit retention. Optional
  OpenTelemetry tracing (`init_tracing`, `trace_prompt_scan`,
  `trace_output_validation`) exports spans to an OTLP endpoint when
  configured.

## Rationale

- **Deterministic and offline:** rule-based detection gives reproducible
  verdicts with no model calls, no API keys, and no network dependency — the
  same guarantee as the scanner (ADR-001). The classifier is a local
  lexical/feature model, not an LLM.
- **Fail-closed by default:** a guard that cannot evaluate must block rather
  than pass, so `fail_closed` turns evaluation errors and empty rule corpora
  into `blocked=True`/`valid=False`.
- **Defense in depth on output:** schema validation, policy rules, and PII
  redaction are independent checks, so a bypass in one layer is caught by
  another.
- **Tamper-evident audit:** HMAC checksums on audit rows make retroactive
  modification detectable, complementing the serve audit chain (ADR-006).
- **Bounded resources:** input/output size caps, JSON-schema size/depth caps,
  and a bounded rate-limiter table prevent memory-exhaustion DoS from
  untrusted callers.
- **Separate admin surface:** read-only health/metrics/rules on a distinct
  port keeps operational endpoints out of the scan path and lets operators
  gate them independently.

## Consequences

- Rule-based detection has false-positive variance and gaps for novel
  obfuscation not in the corpus; rules must be maintained as attack patterns
  evolve (same trade-off as ADR-001).
- The audit HMAC key defaults to a per-process random key, so checksums do
  not survive restarts unless `PICOWATCH_AUDIT_HMAC_KEY` (≥32 chars) is set.
- The rate limiter is in-memory and per-process; it does not coordinate across
  multiple server instances.
- The `watch-server` extra is required for the FastAPI server; the guard
  classes themselves import without FastAPI/pydantic.
- The output guard's JSON-schema check is a structural subset (type, required
  fields), not full JSON Schema validation.
