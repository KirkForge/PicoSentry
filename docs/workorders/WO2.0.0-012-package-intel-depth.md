# WO2.0.0-012 — Package Intelligence: Download Counts + Package Age

**Series:** WO2.0.0 (improvement loop)
**Status:** COMPLETE (CHANGELOG "WO2.0.0-012 package intel depth")
**Owner:** subagent (worktree `wo/2.0.0/package-intel-depth`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/scan/ -m "not slow"`

## Objective
Deepen package intelligence (5/10 → higher). The review flags: "No download counts, maintainer history, package age, namespace collision detection."

## Root cause being addressed
Package intelligence is shallow (17 signals) vs Socket (70+)/Endor (150+). Adding download counts + package age gives operators signal on whether a package is established or suspiciously new.

## Scope
- `picosentry/scan/` — extend `PackageIntel` with `download_count` and `package_age` (first-release date) fields
- `picosentry/scan/_network.py` — fetch download counts / first-release from the registry (PyPI JSON API, npm, etc.) when online; degrade gracefully offline
- `picosentry/scan/rules/` — a rule that flags a package with very low download count + very young age (suspicious new package)
- `picosentry/scan/models.py` — extend the intel model

## Done-condition
- `PackageIntel` carries download_count + package_age
- A rule flags suspiciously-new low-download packages
- Offline mode degrades gracefully (no network = no intel, no crash)
- Precision/recall floors not regressed
- All gates green

## Notes
- Do NOT lower thresholds.
- Do NOT rewrite tests to pass.
- Preserve honest-doc annotations.
