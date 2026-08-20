# WO7.0.0-007 — Scan: PEP 508 dependency parser in advisory collector corrupts 3 dep spec forms

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/pep508-dep-name`)
**Priority:** P1 · Effort S · Risk L
**Scope:** `picosentry/scan/rules/advisory_check.py`, `tests/scan/`

**Gate:** `bash scripts/test.sh fast` + test: dep specs `requests[security]>=2.20`, `requests~=2.20`, `requests; python_version<"3.11"` all extract name `requests` (extras/version/markers stripped).

## Objective
The advisory collector splits dep names with `dep.split(">")[0].split("<")[0]...`. This mangles three real-world PEP 508 forms and produces wrong lookup keys → missed advisories.

## Evidence (verified 2026-08-20, explorer SA-scan; file:line chain)
- `advisory_check.py:182`: name extraction is a chain of `split`s over `<>!~=` and never handles `[extras]`, `~=` (leaves `requests~`), or `;` markers.
- `requests[security]>=2.20` → `"requests[security]"` (lookup key with brackets, no advisory match).
- `requests~=2.20` → `"requests~"` (tilde retained, no match).
- Markers not stripped → `requests; python_version<"3.11"` → `"requests; python_version<\"3.11\""`.

## Deliverables
1. Replace the split chain with a proper PEP 508 name extractor (stdlib `packaging` already a dep — `Requirement(dep).name`).
2. Regression test per the gate covering all three forms.