# WO6.0.0-016 — Watch: decode-budget starvation is advisory-only (clean verdict + ignored flag)

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/decode-budget-starvation`)
**Priority:** P1 · Effort M · Risk M (budget exists for perf — WO5-016)
**Scope:** `picosentry/watch/prompt_guard/normalize.py`, `picosentry/watch/server.py`, `picosentry/watch/gateway.py`, `tests/watch/`

**Gate:** `bash scripts/test.sh fast` + test: the starvation repro (4200 benign b64 blobs + payload at the end) either blocks/WARNs on the payload or the exhausted flag visibly degrades the verdict; output-guard parity for the flag; perf ceilings green.

## Objective
WO5-011's `decode_budget_exhausted` honesty signal exists but nothing downstream reads it — a starved decode still yields a clean verdict.

## Evidence (verified 2026-08-18, explorer SA-AS; live repro t6_starve.py)
4200 unique benign b64 changelog blobs (~403KB, under the 1MB cap) + payload b64 at the end → **blocked=False score=0.0** with `details.decode_budget_exhausted=True` only; the payload alone blocks 0.8. Budget consumed in document order; the hint-priority only bypasses the VARIANT cap, not the bytes burned before the payload. Server returns the verdict as-is; gateway ignores details. (WO6-002's textlike fix may intersect — coordinate.)

## Deliverables
1. Hint-first decode ordering (two-pass: hint-carrying runs first) or budget scaling with input size.
2. `decode_budget_exhausted` → at least WARN-tier verdict (server + gateway honor it); output guard surfaces the flag (parity).
3. Starvation regression test per the gate.
