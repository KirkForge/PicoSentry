# WO2.0.0-011 — Reachability Analysis

**Series:** WO2.0.0 (improvement loop)
**Status:** OPEN
**Owner:** subagent (worktree `wo/2.0.0/reachability`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/scan/ -m "not slow"`

## Objective
Add reachability analysis: determine whether a flagged CVE/vulnerable dependency is actually reachable in the scanned code, not just present in the lockfile.

## Root cause being addressed
The review flags: "No reachability analysis (is the CVE path actually reachable in my code?)" — a key differentiator vs Snyk/Endor.

## Scope
- `picosentry/scan/` — add a reachability pass that maps a vulnerable package's imports/usages in the scanned project to the advisory's affected entry points
- `picosentry/scan/rules/` — a new rule (or extension) that reports reachable vs present-only findings
- `picosentry/scan/models.py` — extend the finding model with a `reachable` flag
- Fixtures + a test for a reachable vs non-reachable case

## Done-condition
- A vulnerable dep that is imported/used is flagged `reachable: true`
- A vulnerable dep that is present but unused is flagged `reachable: false`
- Precision/recall floors (85%/60%) not regressed
- All gates green

## Notes
- Do NOT lower thresholds to make gates green.
- Do NOT rewrite tests to pass.
- Preserve honest-doc annotations.
