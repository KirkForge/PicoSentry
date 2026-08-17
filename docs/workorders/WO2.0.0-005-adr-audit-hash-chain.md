# WO2.0.0-005 — ADR Gap: Audit Hash-Chain

**Series:** WO2.0.0 (improvement loop)
**Status:** UNVERIFIED (spec predates status tracking; series reported COMPLETE — verify scope before reopening)
**Owner:** subagent (worktree `wo/2.0.0/adr-gaps`)
**Gate:** `uv run ruff check` + `uv run mypy picosentry/`

## Objective
Write a new ADR documenting the tamper-evident audit hash-chain in `picosentry/serve/middleware/audit.py`.

## Context
The audit middleware implements a tamper-evident `_AuditChain` with `prev_hash` linking and restart reseeding (`_seed_chain` from the last committed `row_hash`). This is a security-critical design decision with NO ADR.

## Deliverable
- `docs/adr/ADR-006-audit-hash-chain.md` — document the chain design, restart reseed, and tamper-evidence guarantees.

## Done-condition
- ADR-006 exists and accurately describes the implementation.
