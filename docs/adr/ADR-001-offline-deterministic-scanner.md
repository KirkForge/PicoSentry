# ADR-001: Offline deterministic scanning — no model calls in the hot path

**Status:** Accepted  
**Date:** 2026-06

## Context

Supply-chain scanning must be fast, reproducible, and usable in air-gapped or CI environments where outbound network calls to LLM APIs are unavailable or forbidden.

## Decision

All detection logic (54 rules across 7 ecosystems) runs offline against a local rule catalog. No model calls are made during a scan. The prompt-injection classifier (`picosentry watch`) uses a deterministic regex + lexical approach, not an LLM.

## Rationale

- Deterministic output: same package always produces the same result
- No API keys, no latency, no rate limits in CI
- Works fully air-gapped; Docker image bundles all rules
- LLM-based detection has high false-positive variance; rule-based maintains a measurable CI floor (100% fixture pass rate)

## Consequences

- Rules must be maintained manually as new attack patterns emerge
- Detection gaps exist for novel obfuscation not yet in the rule catalog
- A future semantic-LLM tier could augment (not replace) deterministic rules
