# WO7.0.0-013 — Firewall: PyPI scan blind to author/maintainer/repository/provenance — `pypi_metadata.json` written but never read

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/firewall-pypi-metadata`)
**Priority:** P1 · Effort M · Risk L
**Scope:** `picosentry/firewall/scanner.py`, `picosentry/firewall/rules/`, `tests/firewall/`

**Gate:** `bash scripts/test.sh fast` + test: a PyPI package with a suspicious author / abandoned repo / no provenance fires the corresponding rules; npm parity asserted (npm fires ≥6 rules with the same metadata shape, PyPI fires ≥1).

## Objective
The firewall writes `pypi_metadata.json` for PyPI packages but no rule reads it. The npm path fires 6 rules with the same metadata shape; the PyPI path fires 0. PyPI packages get a strictly weaker firewall.

## Evidence (verified 2026-08-20, explorer SA-scan; file:line chain)
- `scanner.py:153-166`: `pypi_metadata.json` is written (author, maintainer, repo, provenance fields).
- No rule under `picosentry/firewall/rules/` reads `pypi_metadata.json` — npm rules consume the equivalent npm metadata; PyPI has no parity rules.

## Deliverables
1. Either write PyPI info fields into the synthetic `pyproject.toml` (so existing rules fire) OR teach the PyPI-targeted rules to read `pypi_metadata.json`.
2. Regression test per the gate (author/repo/provenance rules fire for PyPI).