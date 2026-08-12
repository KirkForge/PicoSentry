# WO3.0.0-003 — Version-Confusion / Version-Squatting Detection

**Series:** WO3.0.0 (improvement loop)
**Status:** OPEN
**Owner:** subagent (worktree `wo/3.0.0/version-confusion`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/scan/ -m "not slow"`

## Objective
Add a rule that flags anomalous package versions — a `0.0.0`/`1.0.0`-style squat on a popular package, or a version that jumps the published sequence.

## Root cause being addressed
No rule flags *version-confusion* (distinct from name-based typosquat and registry-based dep-confusion). `package_intel.py` already extracts `version_signals` — the data is there, the rule isn't.

## Scope
- `picosentry/scan/rules/` — new rule (e.g. `L2-VCONF-001`) that flags a package whose declared version is anomalous (suspiciously low like `0.0.0` on a popular package, or version jumping the published sequence)
- `picosentry/scan/package_intel.py` — use existing `version_signals`
- `picosentry/scan/rules/__init__.py` — register in `RULE_INFO`
- `tests/scan/test_version_confusion.py` — fixtures + tests

## Done-condition
- Rule flags a version-squatting package
- Legitimate version ranges are not flagged
- Precision/recall floors not regressed
- All gates green

## Notes
- Do NOT lower thresholds.
- Do NOT rewrite tests to pass.
- Preserve honest-doc annotations.
