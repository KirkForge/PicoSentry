# WO5.0.0-033 — Serve: webhook wildcard event matching is broken (new, flagged during P0 wave)

**Series:** WO5.0.0 (new 2026-08-18 — verified by worker SA-X while fixing WO5.0.0-008)
**Status:** DONE (2026-08-18, merge `134327f4`, worker SA-AD) — `"*" in wh.events or event in wh.events` in dispatch; semantics documented in the API model; tests: wildcard receives chain.escalated, explicit lists exact.
**Owner:** (unassigned — worktree `wo/5.0.0/webhook-wildcard`)
**Priority:** P1 · Effort S · Risk L
**Scope:** `picosentry/serve/services/webhooks.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + test: webhook registered with `events: ["*"]` receives a dispatch for an event it plausibly matches (kill-chain escalation); explicit event lists still match exactly.

## Objective
The API's default event subscription must actually subscribe.

## Evidence (verified 2026-08-18 during WO5.0.0-008 work)
`WebhookManager.dispatch` matches events by literal membership (`event in wh.events`) — a webhook registered with the API default `events: ["*"]` never receives ANY dispatch: the wildcard is compared literally and matches nothing. Every escalation webhook created with default settings silently never fires. (Found while fixing the name-clobber bug in the same file; left untouched as out of that WO's scope.)

## Deliverables
1. Wildcard semantics (`"*"` matches all dispatchable events) or remove the default and require explicit events (pick one, document in the API model description).
2. Regression test for both wildcard and explicit-list webhooks.
