# WO3.0.0-010 — Tighten Detection Recall Floor

**Series:** WO3.0.0 (improvement loop)
**Status:** COMPLETE (verified in code 2026-08 — see workorders/README.md)
**Owner:** subagent (worktree `wo/3.0.0/recall-floor`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/scan/ -m "not slow"` + mutation benchmark

## Objective
Raise the weakest enforcement point: the 60% mean-recall floor. Tighten it (e.g. to 70%) to force new rules to meet a real standard and catch regressions earlier.

## Root cause being addressed
Detection quality: `tests/scan/test_validation.py:114` enforces `mean_recall < 0.60` — the loosest gate. Raising it improves detection confidence.

## Scope
- `tests/scan/test_validation.py:114` — raise the recall floor (e.g. `0.60` → `0.70`) IF the current rule set already meets it
- If the current corpus does NOT meet a higher floor, identify which rules/fixtures lag and report; do NOT lower the floor to make it pass
- Update `docs/BENCHMARKS.md` if it states the floor (it currently has stale prose about "100%" floor)
- Verify the mutation benchmark floors (75% recall / 25% precision) are still met

## Done-condition
- Recall floor raised to 70% (or the current achieved value, whichever is higher) and the suite passes
- Or: report exactly why a higher floor fails (with fixture-level evidence) without lowering it
- All gates green

## Notes
- Do NOT lower thresholds to make gates green.
- Do NOT rewrite tests to pass.
- Preserve honest-doc annotations.
