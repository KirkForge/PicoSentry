# WO3.0.0-002 — Namespace/Scope Collision Detection

**Series:** WO3.0.0 (improvement loop)
**Status:** COMPLETE (verified in code 2026-08 — see workorders/README.md)
**Owner:** subagent (worktree `wo/3.0.0/namespace-collision`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/scan/ -m "not slow"`

## Objective
Add a rule that detects package namespace/scope collisions — a package squatting a namespace or scope (e.g. `@scope/pkg` shadowing a well-known package, or a new package claiming a reserved org namespace).

## Root cause being addressed
Detection intelligence gap: no rule detects namespace/scope collision. This is a distinct high-signal attack class currently invisible.

## Scope
- `picosentry/scan/rules/` — new rule (e.g. `L2-NSCOL-001`) that flags a package whose name collides with a well-known namespace/scope prefix while being new or low-download
- `picosentry/scan/models.py` — reuse `PackageIntel` (download_count, package_age_days) to scope the rule (low FP: "namespace exists but package is new/low-downloads")
- `picosentry/scan/rules/__init__.py` — register in `RULE_INFO`
- `tests/scan/test_namespace_collision.py` — fixtures + tests (collision flagged, legit scope not flagged)

## Done-condition
- Rule flags a package squatting a well-known namespace/scope when new/low-download
- Legitimate scoped packages are not flagged
- Precision/recall floors (85%/60%) not regressed
- All gates green

## Notes
- Do NOT lower thresholds.
- Do NOT rewrite tests to pass.
- Preserve honest-doc annotations.
