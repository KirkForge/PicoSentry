# WO2.0.0-004 — Package Intelligence

**Series:** WO2.0.0 (improvement loop)
**Status:** OPEN
**Owner:** subagent (worktree `wo/2.0.0/package-intelligence`)
**Gate:** `uv run pytest tests/ -m "not slow"` + `uv run ruff check` + `uv run mypy picosentry/`

## Objective
Improve the scanner's package intelligence: detection quality, rule coverage, and cross-layer correlation.

## Context
- Scanner: 50 rules across 7 ecosystems (cargo, go, maven, npm, nuget, pypi, rubygems).
- Validation: 85% precision / 60% recall (adjusted floors).
- Cross-layer correlation links scan + sandbox + watch findings.

## Scope
- Audit rule catalog for coverage gaps against current supply-chain attack patterns (typosquatting, dependency confusion, malicious post-install, exfiltration).
- Improve detection quality without regressing precision/recall floors.
- Verify cross-layer correlation is correct and dedup works.
- Add an ADR for the LLM watch subsystem (currently a GAP — no ADR exists).

## Root cause being addressed
Detection quality is the product's differentiator; rule coverage and correlation must keep pace with the threat landscape.

## Done-condition
- No regression in precision/recall floors (85% / 60%).
- Rule catalog audited; gaps documented or filled.
- New ADR documents the LLM watch subsystem.

## Notes
- Do NOT lower thresholds to make gates green.
- Do NOT rewrite tests to pass.
- Preserve honest-doc annotations.
