# WO3.0.0-004 — Real-Time OSV Advisory Feed

**Series:** WO3.0.0 (improvement loop)
**Status:** COMPLETE (verified in code 2026-08 — see workorders/README.md)
**Owner:** subagent (worktree `wo/3.0.0/osv-realtime`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/scan/ -m "not slow"`

## Objective
Replace the batch 24h-TTL OSV cache with a real-time advisory subscription (webhook or short-interval poll), so new advisories reach scans without a 24h delay.

## Root cause being addressed
Connected intelligence 5/10: `OSVClient` (`picosentry/scan/intelligence.py:26-30`) caches for 24h; a newly-published advisory won't be seen for up to a day.

## Scope
- `picosentry/scan/intelligence.py` — add a real-time channel: subscribe to OSV webhook (if OSV offers it) or poll with a configurable short interval; reduce/eliminate the 24h cache for the live path
- `picosentry/serve/` — if a subscription service/worker is appropriate, wire it in (or keep it scanner-side, offline-degrading)
- Keep the offline path (local advisory DB) working for air-gapped use
- Config knob for the live interval

## Done-condition
- New advisories are picked up in near-real-time (configurable, default well under 24h)
- Offline mode still works
- All gates green

## Notes
- Do NOT rewrite tests to pass.
- Preserve honest-doc annotations.
- `network` marker is available for network-dependent tests.
